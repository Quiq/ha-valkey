#!/usr/bin/env python3
"""Run command on each redis/sentinel instance."""

import argparse
import sys

import common_redis as common

global CONFIG_FILES, CONFIG, SECRETS, DEBUG


def run_command(args):
    """Run command."""
    domain = CONFIG['domain']
    databases = {k: v['port_offset'] for k, v in CONFIG['services'][args.cluster][args.subcluster].items()}
    databases = {k: databases[k] for k in sorted(databases, key=databases.get)}
    if args.db in databases:
        databases = {args.db: databases[args.db]}
    elif args.db is not None:
        print('No such database in the cluster.')
        print(f'Databases: {list(databases.keys())}')
        sys.exit(1)

    print(f'Cluster: {args.cluster}')
    print(f'Subcluster: {args.subcluster}')
    print(f'Databases and port offsets: {databases}')

    # Resolve host aliases.
    host_aliases = [i for i in CONFIG['instances'][args.cluster][args.subcluster]]
    hostnames = []
    for i in range(1, len(host_aliases)+1):
        host = f'{args.subcluster}{i}.{args.cluster}.{domain}'

        if args.host and args.host != host:
            continue

        hostnames.append(host)

    print(f'Hosts: {hostnames}')
    print()

    if args.list_dbs:
        sys.exit()

    command = args.command
    connections = {}
    if args.show_conns:
        command = 'CLIENT LIST'

    redis_obj = common.Redis(DEBUG, verbose=True)
    for db, port_offset in databases.items():
        print(f'DB: {db}')
        password = SECRETS[args.cluster][args.subcluster][db]['password']
        direct_redis_port = CONFIG['haproxy_redis_local_ssl_port'] + port_offset
        sentinel_port = CONFIG['haproxy_sentinel_ssl_port'] + port_offset

        port = direct_redis_port
        if args.sentinel:
            port = sentinel_port

        for host in hostnames:
            val = redis_obj.run_command(host, port, password, command)
            if args.show_conns:
                for i in val:
                    k = f'name={i["name"]} addr={i["addr"].split(":")[0]}'
                    if k not in connections:
                        connections[k] = 1
                    connections[k] += 1
            else:
                print(val)

        if args.show_conns:
            print('Connection collected from all the hosts:')
            for k, v in sorted(connections.items()):
                print(f'{v:>5}  {k.split()[0]:<30}  {k.split()[1]:<20}')

        print()


def main():
    """Main."""
    parser = argparse.ArgumentParser(description='Run command on each redis/sentinel instance')
    parser.add_argument('--cluster', '-c', help='cluster name', required=True)
    parser.add_argument('--subcluster', '-s', help='subcluster name', default='redisdb')
    parser.add_argument('--db', '-d', help='redis db name')
    parser.add_argument('--host', help='redis host to make changes instead of all')
    parser.add_argument('--sentinel', help='apply to sentinel instead of redis', action='store_true')
    parser.add_argument('--command', help='command to run')
    parser.add_argument('--list-dbs', '-l', help='show the database list', action='store_true')
    parser.add_argument('--show-conns', help='show connections', action='store_true')
    parser.add_argument('--debug', help='debug mode', action='store_true')
    args = parser.parse_args()

    global CONFIG_FILES, CONFIG, SECRETS, DEBUG
    DEBUG = args.debug
    CONFIG_FILES, CONFIG, SECRETS = common.read_redis_configs(DEBUG)

    common.check_arguments(args, CONFIG_FILES, CONFIG, SECRETS, db_arg_check=False)

    if not args.list_dbs and not args.command and not args.show_conns:
        print(f'ERROR: you need to specify one of the args: --command, --list-dbs, --show-conns')
        sys.exit(1)

    run_command(args)


if __name__ == '__main__':
    main()
