#!/usr/bin/env python3
"""Get Redis master IP. Used by ansible to update redisdb hosts."""

import argparse
import socket

import common_redis as common

global CONFIG_FILES, CONFIG, SECRETS, DEBUG


def get_current_master(cluster, subcluster, db):
    """Get current master."""
    password = SECRETS[cluster][subcluster][db]['password']
    port_offset = CONFIG['services'][cluster][subcluster][db]['port_offset']
    sentinel_port = CONFIG['haproxy_sentinel_ssl_port'] + port_offset

    # Resolve host aliases.
    host_aliases = [i for i in CONFIG['instances'][cluster][subcluster]]
    alias_ips = {}
    for i in range(1, len(host_aliases)+1):
        host = f'{subcluster}{i}.{cluster}.example.com'

        ip = socket.gethostbyname(host)
        alias_ips[host_aliases[i-1]] = ip

    redis_obj = common.Redis(DEBUG, verbose=False, timeout=1)
    for host in alias_ips.values():
        # Query sentinel one by one until first response.
        master_ip = redis_obj.run_command(host, sentinel_port, password, 'SENTINEL GET-MASTER-ADDR-BY-NAME default')
        if master_ip:
            break

    if not master_ip:
        # Return the IP of the first db, usually srv1.
        master_ip = alias_ips[host_aliases[0]]
    else:
        master_ip = master_ip[0].decode()

    print(master_ip)


def main():
    """Main."""
    parser = argparse.ArgumentParser(description='Get Redis master IP')
    parser.add_argument('--cluster', '-c', help='cluster name', required=True)
    parser.add_argument('--subcluster', '-s', help='subcluster name', default='redisdb')
    parser.add_argument('--db', '-d', help='redis db name', required=True)
    parser.add_argument('--debug', help='debug mode', action='store_true')
    args = parser.parse_args()

    global CONFIG_FILES, CONFIG, SECRETS, DEBUG
    DEBUG = args.debug
    CONFIG_FILES, CONFIG, SECRETS = common.read_redis_configs(DEBUG)

    get_current_master(args.cluster, args.subcluster, args.db)


if __name__ == '__main__':
    main()
