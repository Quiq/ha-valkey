#!/usr/bin/env python3
"""Redis database status script."""

import argparse
import socket
import sys
import time

import common_redis as common

global CONFIG_FILES, CONFIG, SECRETS, DEBUG


def show_status(cluster, subcluster, db, list_only, no_sentinel):
    """Show status on a specific cluster and subcluster."""
    domain = CONFIG['domain']
    databases = {k: v['port_offset'] for k, v in CONFIG['services'][cluster][subcluster].items()}
    databases = {k: databases[k] for k in sorted(databases, key=databases.get)}
    if db in databases:
        databases = {db: databases[db]}
    elif db is not None:
        print(f'No such database for "{cluster}" cluster and "{subcluster}" subcluster.')
        print(f'Valid databases are: {list(databases.keys())}')
        sys.exit(1)

    print(f'Cluster: {cluster}')
    print(f'Subcluster: {subcluster}')
    print(f'Databases and port offsets: {databases}')

    # Resolve host aliases.
    host_aliases = [i for i in CONFIG['instances'][cluster][subcluster]]
    hostnames = {}
    for i in range(1, len(host_aliases)+1):
        host = f'{subcluster}{i}.{cluster}.{domain}'

        hostnames[host] = socket.gethostbyname(host)

    print(f'Hosts: {hostnames}')
    print()

    if list_only:
        sys.exit()

    # Draw table header.
    print('-'*150)
    print('%-25s' % 'Database', end='')
    print('%-15s' % 'Redis Port', end='')
    for host in hostnames:
        print(f'{host:35}', end='')

    print()
    print(' '*25, end='')
    print(' '*15, end='')
    for ip in hostnames.values():
        print(f'{ip:35}', end='')

    print()
    print('-'*150)

    redis_obj = common.Redis(DEBUG, verbose=False)
    for db, port_offset in databases.items():
        password = SECRETS[cluster][subcluster][db]['password']
        redis_port = CONFIG['haproxy_redis_ssl_port'] + port_offset
        direct_redis_port = CONFIG['haproxy_redis_local_ssl_port'] + port_offset
        sentinel_port = CONFIG['haproxy_sentinel_ssl_port'] + port_offset

        redis_info = {}
        sentinel_info = {}
        config_info = {}
        for host in hostnames:
            # Straight Redis via HAProxy SSL.
            redis_info[host] = redis_obj.run_command(host, direct_redis_port, password, ['INFO', 'replication'])
            config_info[host] = redis_obj.run_command(host, direct_redis_port, password, 'CONFIG GET min-slaves-to-write')

            if no_sentinel:
                continue

            # Sentinel via HAProxy SSL.
            sentinel_info[host] = redis_obj.run_command(host, sentinel_port, password, 'SENTINEL GET-MASTER-ADDR-BY-NAME default')

        print(f'{db:25}', end='')
        print(f'{redis_port:<15}', end='')
        master_ip = None
        master_host = None
        alien_master = False
        slave_of_itself = False
        alive_hostnames = hostnames.copy()
        for host in hostnames:
            role = 'DOWN 🔻'
            if redis_info[host]:
                role = redis_info[host]['role']
            else:
                # Re-init redis_obj with much lower timeout.
                redis_obj = common.Redis(DEBUG, verbose=False, timeout=1)
                del alive_hostnames[host]

            if role == 'master':
                role = role.upper()
                master_ip = hostnames[host]
                master_host = host
                slave_count = 0
                for i in redis_info[host].keys():
                    if i[:-1] == 'slave':
                        slave_count += 1

            elif role == 'slave':
                if redis_info[host]['master_host'] == 'localhost':
                    role = 'slave of itself ⚠️'
                    slave_of_itself = True
                elif redis_info[host]['master_host'] not in hostnames.values():
                    role = f'slave of {redis_info[host]["master_host"]} 👽'
                    alien_master = True

            print(f'{role:35}', end='')

        print()
        if slave_of_itself:
            print(f' 👉 Error: one of the slaves has not reconfigured yet.')
            print(f' 💡 It is possible in case of failover or redis was restarted and sentinels have not reconfigured it yet (may take up to 5m).')
            print()

        if alien_master:
            print(f' 👉 Error: one of the slaves has master host outside of this subcluster 🛸')
            print(f' 💡 Looks like you made or about to make a failover between subclusters.')
            print()

        if not master_host:
            print(f' 👉 Error: no master detected in this subcluster.')
            print(f' 💡 Looks like the master is down and there is ongoing failover process. Check back again.')
            print()
            continue

        slaves = [redis_info[master_host][f'slave{i}']['ip'] for i in range(slave_count)]
        slaves.sort()
        nonmasters = list(alive_hostnames.values())
        del nonmasters[nonmasters.index(master_ip)]
        nonmasters.sort()

        if len(alive_hostnames)-1 == 0:
            print(f' 👉 Error: master host reports {slave_count} slaves {slaves} and neither in this subcluster.')
            print(f' 💡 Looks like you are about to make a failover between subclusters.')
            print()
            continue

        if slave_count > len(alive_hostnames)-1:
            print(f' 👉 Error: master host reports {slave_count} slaves instead of {len(alive_hostnames)-1}: {slaves} vs {nonmasters}')
            print(f' 💡 Looks like some slaves are not the part of this subcluster, probably you made or about to make a failover between subclusters.')
            print()
            continue

        if slaves != nonmasters:
            print(f' 👉 Error: slaves reported by master do not correspond to the rest of the hosts: {slaves} vs {nonmasters}')
            print(f' 💡 It is possible in case of failover or redis was restarted and sentinels have not reconfigured it yet (may take up to 5m).')
            print()
            continue

        # Test write/read to the redis app port (haproxy frontend, not the direct redis port).
        test_redis_write_read(redis_obj, slaves, master_ip, redis_port, password)

        # Check min-slaves-to-write.
        for host in alive_hostnames:
            val = config_info[host][1].decode()
            if val != '1':
                print(f' 👉 Error: {host} is reporting min-slaves-to-write set to {val} instead of 1.')
                print(f' 💡 You need to run: CONFIG SET min-slaves-to-write 1')
                print()

        if no_sentinel:
            continue

        # Check master host with sentinels.
        for host in alive_hostnames:
            if not sentinel_info[host]:
                print(f' 👉 Error: sentinel seems down at {host}.')
                print()
                continue

            sentinel_master_ip = sentinel_info[host][0].decode()
            if sentinel_master_ip != master_ip:
                print(f' 👉 Error: sentinel at {host} reports master ip {sentinel_master_ip} instead of {master_ip}.')
                print()


def test_redis_write_read(redis_obj, slaves, master_ip, redis_port, password):
    """Write to master and read from each of the slaves."""
    # Write to master.
    timestamp = str(time.time())
    output = redis_obj.run_command(master_ip, redis_port, password, f'SETEX status_script_test 60 {timestamp}')
    if not output or output != b'OK':
        print(f' 👉 Error: cannot SETEX status_script_test value: {output}.')
        print(' 💡 Redis frontend seems disabled on haproxy.')
        print()
        return

    # Read from slaves. Actually, it reads from the master through haproxy frontend on slave.
    for i in slaves:
        output = redis_obj.run_command(i, redis_port, password, 'GET status_script_test')
        if not output or timestamp != output.decode():
            print(f' 👉 Error: slave {i} should have returned {timestamp} instead of {output} on "GET status_script_test".')
            print(' 💡 Redis frontend seems disabled on haproxy or there is a discrepancy.')
            print()


def main():
    """Main."""
    parser = argparse.ArgumentParser(description='Redis database status script')
    parser.add_argument('--cluster', '-c', help='cluster name', required=True)
    parser.add_argument('--subcluster', '-s', help='subcluster name', default='redisdb')
    parser.add_argument('--db', '-d', help='redis db name')
    parser.add_argument('--list-only', '-l', help='Show the database list only, no checks', action='store_true')
    parser.add_argument('--no-sentinel', '-n', help='Do not query sentinel for consistency check', action='store_true')
    parser.add_argument('--debug', help='debug mode', action='store_true')
    args = parser.parse_args()

    global CONFIG_FILES, CONFIG, SECRETS, DEBUG
    DEBUG = args.debug
    CONFIG_FILES, CONFIG, SECRETS = common.read_redis_configs(DEBUG)

    common.check_arguments(args, CONFIG_FILES, CONFIG, SECRETS, db_arg_check=False)

    show_status(args.cluster, args.subcluster, args.db, args.list_only, args.no_sentinel)


if __name__ == '__main__':
    main()
