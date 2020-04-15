#!/usr/bin/env python3
"""Redis failover script.

You will be prompted for confirmation to do a failover or disable frontends.
"""

import argparse
import datetime
import json
import os
import pprint
import socket
import ssl
import sys
import time

import redis
import requests

import common_redis as common

TASK_NAME = os.path.basename(__file__).split('.')[0]

global CONFIG_FILES, CONFIG, SECRETS, DEBUG, SKIP_SLACK


def do_failover(cluster, subcluster, db, enable_fe, disable_fe, target_subcluster, skip_confirm):
    """Perform failover for redis db."""
    domain = CONFIG['domain']
    password = SECRETS[cluster][subcluster][db]['password']
    port_offset = CONFIG['services'][cluster][subcluster][db]['port_offset']
    redis_port = CONFIG['haproxy_redis_ssl_port'] + port_offset
    direct_redis_port = CONFIG['haproxy_redis_local_ssl_port'] + port_offset
    sentinel_port = CONFIG['haproxy_sentinel_ssl_port'] + port_offset
    haproxy_api_port = CONFIG['haproxy_api_port'] + port_offset
    is_error = False

    subclusters = [subcluster]
    if target_subcluster:
        subclusters.append(target_subcluster)

    # Resolve host aliases.
    ip_aliases = {}
    ip_hosts = {}
    subcluster_hosts = {}
    for subc in subclusters:
        host_aliases = [i for i in CONFIG['instances'][cluster][subc]]
        subcluster_hosts[subc] = []
        for i in range(1, len(host_aliases)+1):
            host = f'{subcluster}{i}.{cluster}.{domain}'

            ip = socket.gethostbyname(host)
            ip_aliases[ip] = host_aliases[i-1]
            ip_hosts[ip] = host
            subcluster_hosts[subc].append(host)

        subcluster_hosts[subc].sort()

    print(f'Cluster:    {cluster}')
    print(f'Subcluster: {subcluster}')
    print(f'Database:   {db}')
    print(f'Hosts:      {ip_hosts}')
    print()

    redis_obj = common.Redis(DEBUG, verbose=True)
    haproxy = Haproxy(haproxy_api_port)

    # This is a separate and mostly a recovery step in case it's needed.
    # It enables frontend and healthchecks, it's not a part of failover.
    if enable_fe:
        print('Enabling healthchecks and frontend on haproxy...')
        haproxy.healthcheck('enable', ip_aliases.values(), ip_hosts.values())
        haproxy.frontend('enable', ip_hosts.values())
        haproxy.execute()

        print()
        print('All done.')
        sys.exit(0)

    print('Getting current master...')
    for host in ip_hosts.values():
        # Query sentinel one by one until first response.
        master_ip = redis_obj.run_command(host, sentinel_port, password, 'SENTINEL GET-MASTER-ADDR-BY-NAME default')
        if master_ip:
            break

    if not master_ip:
        print(' 😡 ERROR: cannot determine the current master.')
        sys.exit(1)

    master_ip = master_ip[0].decode()
    if master_ip not in ip_hosts or ip_hosts[master_ip] not in subcluster_hosts[subcluster]:
        print()
        print(f' 😡 ERROR: master host {master_ip} is outside of this subcluster.')
        print(f' 💡 We cannot do the failover neither within this subcluster nor from this to other.')
        sys.exit(1)

    print()
    print(f'Current master 👉 {ip_hosts[master_ip]} {master_ip} 👈')
    print()

    # Check slaves.
    if target_subcluster:
        # We need all 3 slaves on the target subcluster to be alive and 2 down on the source (redis stopped).
        print('Check redis aliveness on the required slaves...')
        slave_status = {}
        slave_status['online'] = subcluster_hosts[target_subcluster]
        slave_status['offline'] = subcluster_hosts[subcluster][:]
        del slave_status['offline'][slave_status['offline'].index(ip_hosts[master_ip])]

        for status, hosts in slave_status.items():
            for host in hosts:
                data = redis_obj.run_command(host, direct_redis_port, password, 'PING')
                if status == 'online' and not data:
                    print(f' 😡 ERROR: {host} should be online before starting failover to the other subcluster.')
                    print(f' 💡 All hosts that should be online: {slave_status["online"]}')
                    print(f' 💡 We cannot do a failover without all necessary slaves to be up.')
                    sys.exit(1)
                elif status == 'offline' and data:
                    print(f' 😡 ERROR: {host} should be offline before starting failover to the other subcluster.')
                    print(f' 💡 All hosts that should be offline: {slave_status["offline"]}')
                    print(f' 💡 We should stop redis container on those hosts.')
                    sys.exit(1)

        print(' ✅ All good. Slaves in the source subcluster are down as expected.')
        print()
    else:
        # We need all 2 slaves to be alive.
        print('Checking what slaves are reported by master...')
        redis_info = redis_obj.run_command(ip_hosts[master_ip], direct_redis_port, password, ['INFO', 'replication'])
        print()
        slave_count = 0
        for i in redis_info.keys():
            if i[:-1] == 'slave':
                slave_count += 1

        slaves = [redis_info[f'slave{i}']['ip'] for i in range(slave_count)]
        slaves.sort()
        nonmasters = list(ip_hosts.keys())
        del nonmasters[nonmasters.index(master_ip)]
        nonmasters.sort()
        if slaves != nonmasters:
            print(f' 😡 ERROR: slaves reported by master do not correspond to the rest of the hosts: {slaves} vs {nonmasters}')
            print(f' 💡 We cannot do the failover within this subcluster. We may do one from this to other subcluster.')
            sys.exit(1)

        # Don't proceed if we have replication lag
        print('Checking replication...')
        output = redis_obj.run_command(ip_hosts[master_ip], direct_redis_port, password, f'WAIT {slave_count} 1000')
        if slave_count != output:
            print(f' 😡 ERROR: expecting {output} slaves to acknowledge instead of {slave_count}, please check replication.')
            sys.exit(1)

    print()
    if disable_fe:
        print('Confirm with yes to disable frontends (step 1 only): ', end='')
    else:
        print('Subscribing to all sentinels on +switch-master channel...')
        switch_pubsubs = sentinel_pubsubs(ip_hosts.values(), sentinel_port, password, '+switch-master')
        print('Subscribing to all sentinels on +failover-end channel...')
        end_pubsubs = sentinel_pubsubs(ip_hosts.values(), sentinel_port, password, '+failover-end')
        print('Done.')
        print()

        if len(switch_pubsubs) + len(end_pubsubs) != len(ip_hosts) * 2:
            print('⚠️  It is better not to do the failover when some sentinels are down!')
            sys.exit(1)

        if target_subcluster:
            print('You are about to make a failover between subclusters:')
            print(f' * source: {subcluster}')
            print(f' * target: {target_subcluster}')

    if not skip_confirm:
        print('Confirm with yes to start failover: ', end='')
        try:
            if input().lower() != 'yes':
                print(' CANCELED')
                sys.exit(0)
        except KeyboardInterrupt:
            print(' CANCELED')
            sys.exit(0)

    start = time.time()
    print(f'Start: {datetime.datetime.now().isoformat()}')
    print()

    print(f'*** Step 1 ***  {datetime.datetime.now().isoformat()}')
    print('Disabling healthchecks and frontends on haproxy, terminating sessions...')
    haproxy.healthcheck('disable', ip_aliases.values(), ip_hosts.values())
    haproxy.frontend('disable', ip_hosts.values())
    haproxy.sessions('shutdown', ip_hosts.values(), ip_aliases[master_ip])
    haproxy.execute()

    print('Verifying all sessions are closed...')
    hosts = list(ip_hosts.values())
    while hosts:
        output = haproxy.call_haproxy_api(hosts[-1], ['show sess'])
        if 'fe=api_loopback_ssl' in output and 'fe=ft_redis_ssl' not in output:
            hosts.pop()

    if disable_fe:
        print()
        print('All done.')
        sys.exit(0)

    print('Done.')
    print()

    print(f'*** Step 2 ***  {datetime.datetime.now().isoformat()}')
    print('Killing clients and waiting on master to propagate all the changes to slaves...')
    if target_subcluster:
        slave_count = len(slave_status['online'])
    else:
        slave_count = len(ip_hosts)-1

    output = redis_obj.run_command(ip_hosts[master_ip], direct_redis_port, password, f'CLIENT KILL TYPE NORMAL TYPE PUBSUB')
    if type(output) != int:
        print(f' 😡 ERROR: expecting {output} to be integer count of clients killed.')
        print('Enabling healthchecks and frontend on haproxy...')
        haproxy.healthcheck('enable', ip_aliases.values(), ip_hosts.values())
        haproxy.frontend('enable', ip_hosts.values())
        haproxy.execute()
        sys.exit(1)

    output = redis_obj.run_command(ip_hosts[master_ip], direct_redis_port, password, f'WAIT {slave_count} 5000')
    if slave_count != output:
        print(f' 😡 ERROR: expecting {output} slaves to acknowledge instead of {slave_count}, please check replication.')
        print('Enabling healthchecks and frontend on haproxy...')
        haproxy.healthcheck('enable', ip_aliases.values(), ip_hosts.values())
        haproxy.frontend('enable', ip_hosts.values())
        haproxy.execute()
        sys.exit(1)

    print('Done.')
    print()

    print(f'*** Step 3 ***  {datetime.datetime.now().isoformat()}')
    print('Triggering failover...')
    for host in ip_hosts.values():
        # Query sentinel one by one until first response.
        output = redis_obj.run_command(host, sentinel_port, password, 'SENTINEL FAILOVER default')
        if output:
            print(output.decode())
            break

    if not output:
        print(' 😡 ERROR: cannot do failover on sentinel.')
        sys.exit(1)

    print()

    print(f'*** Step 4 ***  {datetime.datetime.now().isoformat()}')
    print('Waiting for a new master message from +switch-channel...')
    msg = None
    while not msg:
        for host, pubsub in switch_pubsubs.items():
            msg = pubsub.get_message(ignore_subscribe_messages=True)
            if msg:
                new_master_ip = msg['data'].decode().split()[3]
                break

    print(f'Got response from {host}.')
    print()
    print(f'New master 💚 {ip_hosts[new_master_ip]} {new_master_ip} 💚')
    print()

    print(f'*** Step 5 ***  {datetime.datetime.now().isoformat()}')
    print('Setting min-slaves-to-write on new master...')
    output = redis_obj.run_command(ip_hosts[new_master_ip], direct_redis_port, password, 'CONFIG SET min-slaves-to-write 0')
    if output is not True:
        is_error = True
        print(f' 😡 ERROR: cannot set config min-slaves-to-write: {output}.')

    print('Done.')
    print()

    print(f'*** Step 6 ***  {datetime.datetime.now().isoformat()}')
    print('Re-routing traffic to the new master and enabling frontend...')
    if target_subcluster:
        # Run this on target subcluster
        haproxy.health('up', subcluster_hosts[target_subcluster], ip_aliases[new_master_ip])
        haproxy.frontend('enable', ip_hosts.values())
        haproxy.execute()
    else:
        # The regular failover.
        haproxy.health('up', ip_hosts.values(), ip_aliases[new_master_ip])
        haproxy.health('down', ip_hosts.values(), ip_aliases[master_ip])
        haproxy.frontend('enable', ip_hosts.values())
        haproxy.execute()

    print('Done.')
    print()

    end = time.time()
    print(f'End: {datetime.datetime.now().isoformat()}')
    print(f'Duration: {end-start:0.6f}s')
    print()

    print(f'*** Step 7 ***  {datetime.datetime.now().isoformat()}')
    print('Testing write to the new master via haproxy frontend...')
    timestamp = str(time.time())
    output = redis_obj.run_command(ip_hosts[new_master_ip], redis_port, password, f'SET failover_check {timestamp}')
    if not output or output != b'OK':
        print(f' 😡 ERROR: cannot SET failover_check value: {output}.')
        print(' 💡 Redis frontend seems disabled on haproxy.')
        print(' 💡 Re-run the same command with --enable-fe to enable frontend and healthchecks.')
        sys.exit(1)

    print('Done.')
    print()

    print(f'*** Step 8 ***  {datetime.datetime.now().isoformat()}')
    print('Waiting for the message on +failover-end channel...')
    msg = None
    while not msg:
        for host, pubsub in end_pubsubs.items():
            msg = pubsub.get_message(ignore_subscribe_messages=True)
            if msg:
                # Here we get an old master IP, not sure we need to verify that.
                # This message indicates the end of failover.
                break

    print(f'Got response from {host}.')
    print()

    print(f'*** Step 9 ***  {datetime.datetime.now().isoformat()}')
    print('Testing read from the new master via haproxy frontend on slaves...')
    if target_subcluster:
        slaves = slave_status['online']
    else:
        slaves = list(ip_hosts.values())
        del slaves[slaves.index(ip_hosts[new_master_ip])]

    for i in slaves:
        output = redis_obj.run_command(i, redis_port, password, 'GET failover_check')
        if not output or timestamp != output.decode():
            is_error = True
            print(f' 😡 ERROR: slave {i} should have returned {timestamp} instead of {output} on "GET failover_check".')
            print(' 💡 Redis frontend seems disabled on haproxy or there is a discrepancy.')

    print('Done.')
    print()

    print(f'*** Step 10 ***  {datetime.datetime.now().isoformat()}')
    print('Setting min-slaves-to-write back on new master...')
    output = redis_obj.run_command(ip_hosts[new_master_ip], direct_redis_port, password, 'CONFIG SET min-slaves-to-write 1')
    if output is not True:
        is_error = True
        print(f' 😡 ERROR: cannot set config min-slaves-to-write: {output}.')

    print('Done.')
    print()

    print(f'*** Step 11 ***  {datetime.datetime.now().isoformat()}')
    print('Waiting for old master to become a slave...')
    while True:
        output = redis_obj.run_command(ip_hosts[master_ip], direct_redis_port, password, ['INFO', 'replication'])
        if output and output['role'] == 'slave':
            break

        # It takes about 3-4s for old master to be reconfigured as slave.
        time.sleep(1)

    print('Done.')
    print()

    print(f'*** Step 12 ***  {datetime.datetime.now().isoformat()}')
    print('Re-enabling healthchecks on haproxy...')
    if target_subcluster:
        haproxy.healthcheck('enable', ip_aliases.values(), subcluster_hosts[target_subcluster])
        haproxy.execute()
    else:
        haproxy.healthcheck('enable', ip_aliases.values(), ip_hosts.values())
        haproxy.execute()

    print('Done.')
    print()

    print(f'Failover time: {end-start:0.6f}s.')
    print(f'Total time:    {time.time()-start:0.6f}s.')
    print()
    print(f'Old master: {ip_hosts[master_ip]} {master_ip}')
    print(f'New master: {ip_hosts[new_master_ip]} {new_master_ip}')
    print()
    if is_error:
        print(' 😡 THERE ARE SOME ERRORS, SEE ABOVE 👆')
        sys.exit(1)
    else:
        print(' ✅ All good.')

    user = os.getenv('USER')
    if user == '':
        user = os.getenv('SUDO_USER')

    message = f'The manual redis failover has been made for `{db}` db from {ip_hosts[master_ip]} `{master_ip}` to {ip_hosts[new_master_ip]} `{new_master_ip}` by {user}.'
    notify_slack(cluster, db, message)


class Haproxy:

    # We form haproxy commands and then execute them in as few batches as possible to speedup failover
    def __init__(self, port):
        self.commands = {}
        self.port = port

    def healthcheck(self, action, ip_aliases, ip_hosts):
        health_commands = []
        for alias in set(ip_aliases):
            health_commands.extend([
                f'{action} health {alias}/redis1',
                f'{action} health {alias}/redis2',
                f'{action} health {alias}/redis3'
            ])

        for host in ip_hosts:
            if host not in self.commands:
                self.commands[host] = []

            self.commands[host].extend(health_commands)

    def health(self, action, ip_hosts, master_alias):
        health_commands = [
            f'set server {master_alias}/redis1 health {action}',
            f'set server {master_alias}/redis2 health {action}',
            f'set server {master_alias}/redis3 health {action}'
        ]
        for host in ip_hosts:
            if host not in self.commands:
                self.commands[host] = []

            self.commands[host].extend(health_commands)

    def frontend(self, action, ip_hosts):
        health_commands = [f"{action} frontend ft_redis_ssl"]
        for host in ip_hosts:
            if host not in self.commands:
                self.commands[host] = []

            self.commands[host].extend(health_commands)

    def sessions(self, action, ip_hosts, master_alias):
        health_commands = [
            f'{action} sessions server {master_alias}/redis1',
            f'{action} sessions server {master_alias}/redis2',
            f'{action} sessions server {master_alias}/redis3'
        ]
        for host in ip_hosts:
            if host not in self.commands:
                self.commands[host] = []

            self.commands[host].extend(health_commands)

    def execute(self):
        for host, commands in self.commands.items():
            self.call_haproxy_api(host, commands)

        self.commands = {}

    def call_haproxy_api(self, host, commands):
        """Communicate with haproxy api via socket."""
        print(f'- {host}:{self.port}')
        pprint.pprint(commands)
        cmd = '\n'.join(commands) + '\n'

        # XXX Investigate TLS auth with SNIXXX
        # https://www.haproxy.com/blog/enhanced-ssl-load-balancing-with-server-name-indication-sni-tls-extension/
        # https://discourse.haproxy.org/t/log-sni-in-tcp-mode/1534
        # context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # context.load_verify_locations(CONFIG_FILES['TLS_CA_CERTS'])
        # context.load_cert_chain(CONFIG_FILES['TLS_CERT'], CONFIG_FILES['TLS_CERT_KEY'], '')
        # TLS client auth.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(common.TIMEOUT)
            # w = context.wrap_socket(s, server_hostname=host)
            w = ssl.wrap_socket(s, keyfile=CONFIG_FILES['TLS_CERT_KEY'], certfile=CONFIG_FILES['TLS_CERT'])
            w.connect((host, self.port))
            w.send(cmd.encode())

            output = ''
            data = w.recv(8192)
            while data:
                output += data.decode()
                data = w.recv(8192)

            w.close()
            if DEBUG:
                print('haproxy response:')
                print(output.strip())

            return output


def sentinel_pubsubs(hosts, port, password, channel):
    """Subscribe to all sentinels."""
    pubsubs = {}
    for host in hosts:
        try:
            print(f'- {host}:{port} SUBSCRIBE {channel}')
            r = redis.Redis(host=host, port=port, password=password,
                            socket_connect_timeout=common.TIMEOUT, ssl=True, ssl_ca_certs=CONFIG_FILES['TLS_CA_CERTS'])
            r.ping()
            pubsubs[host] = r.pubsub()
            pubsubs[host].subscribe(channel)
        except (redis.exceptions.ConnectionError, redis.exceptions.ResponseError, redis.exceptions.TimeoutError) as err:
            print(f'WARN: sentinel error: {err}')

    if not pubsubs:
        print(f' 😡 ERROR: unable to subscribe to any of sentinels on channel {channel}.')
        sys.exit(1)

    return pubsubs


def notify_slack(cluster, db, message):
    """Send message to Slack."""
    if not CONFIG['slack_hook']:
        return

    print('Sending message to Slack...')

    SLACK_CONFIG = {
        'username': TASK_NAME,
        'icon_emoji': ':smile:',
        'channel': '#' + CONFIG['slack_channel'],
        'text': message
    }

    requests.post(CONFIG['slack_hook'], data=json.dumps(SLACK_CONFIG))


def select_masters(cluster, subcluster, host):
    # """Select all masters for specific host."""

    print(f'Selecting all master db\'s for host "{host}"...')

    databases = {k: v['port_offset'] for k, v in CONFIG['services'][cluster][subcluster].items()}
    databases = {k: databases[k] for k in sorted(databases, key=databases.get)}

    master_dbs = []

    redis_obj = common.Redis(DEBUG, verbose=False)
    for db, port_offset in databases.items():
        password = SECRETS[cluster][subcluster][db]['password']
        direct_redis_port = CONFIG['haproxy_redis_local_ssl_port'] + port_offset

        redis_info = {}
        # Straight Redis via HAProxy SSL.
        redis_info[host] = redis_obj.run_command(host, direct_redis_port, password, ['INFO', 'replication'])
        role = redis_info[host]['role']

        if role == 'master':
            print(f'Master db: {db}')
            master_dbs.append(db)

    return master_dbs


def main():
    """Main."""
    parser = argparse.ArgumentParser(description='Redis failover script')
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument('--cluster', '-c', help='cluster name', required=True)
    parser.add_argument('--subcluster', '-s', help='subcluster name', default='redisdb')
    group.add_argument('--db', '-d', help='redis db name')
    parser.add_argument('--debug', help='debug mode', action='store_true')
    parser.add_argument('--enable-fe', help='enable frontends and healthchecks (not a part of failover)', action='store_true')
    parser.add_argument('--disable-fe', help='disable frontends and healthchecks (not a part of failover)', action='store_true')
    parser.add_argument('--target-subcluster', '-t', help='target subcluster for failover between subclusters')
    group.add_argument('--host', help='failover all masters from this host. Useful with --skip-confirm')
    parser.add_argument('--skip-slack', help='skip slack notifications', action='store_true')
    parser.add_argument('--skip-confirm', help='skip confirmation, do failover without prompt', action='store_true')
    args = parser.parse_args()

    global CONFIG_FILES, CONFIG, SECRETS, DEBUG, SKIP_SLACK
    DEBUG = args.debug
    SKIP_SLACK = args.skip_slack
    CONFIG_FILES, CONFIG, SECRETS = common.read_redis_configs(DEBUG)

    common.check_arguments(args, CONFIG_FILES, CONFIG, SECRETS, db_arg_check=False)

    if args.host:
        master_dbs = select_masters(args.cluster, args.subcluster, args.host)
        print()
        print(f'Failover masters from "{args.host}":')
        print()
        for master_db in master_dbs:
            do_failover(args.cluster, args.subcluster, master_db, args.enable_fe, args.disable_fe, args.target_subcluster, args.skip_confirm)
    else:
        do_failover(args.cluster, args.subcluster, args.db, args.enable_fe, args.disable_fe, args.target_subcluster, args.skip_confirm)


if __name__ == '__main__':
    main()
