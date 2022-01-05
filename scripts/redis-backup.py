#!/usr/bin/env python3
"""Create backup of redis dbs and upload to S3.

- No backup on master host for a given db
- Do backup on slaves for a given db
- Upload backup to S3 only from the first slave (IPs sorted) for a given db
"""

import argparse
import datetime
import os
import subprocess
import sys
import time

import boto3
import requests
import yaml

import common_redis as common

TASK_NAME = os.path.basename(__file__).split('.')[0]
CONFIG_FILE = '/opt/redis-backup-config.yml'

HOSTNAME = os.uname()[1]
HOSTALIAS = HOSTNAME.replace('.example.com', '')
CLUSTER = 'testcluster1'

SUBCLUSTER = HOSTALIAS[:-1]

S3 = boto3.resource('s3')
S3_BUCKET = 'example-backups'


def run_backup(db, debug, force):
    """Run backup."""
    # Read config.
    with open(CONFIG_FILE, 'r') as config_file:
        CONFIG = yaml.safe_load(config_file)

    databases = {k: v['port_offset'] for k, v in CONFIG['databases'].items()}
    databases = {k: databases[k] for k in sorted(databases, key=databases.get)}
    if db in databases:
        databases = {db: databases[db]}
    elif db is not None:
        print('No such database in the cluster.')
        print(f'Databases: {list(databases.keys())}')
        sys.exit(1)

    print(f'Cluster: {CLUSTER}')
    print(f'Subcluster: {SUBCLUSTER}')
    print(f'Databases and port offsets: {databases}')
    print()

    redis_obj = common.Redis(debug, verbose=True)
    is_error = False
    for db, port_offset in databases.items():
        print('###' * 30)
        print(f'DB: {db}')
        password = CONFIG['databases'][db]['password']
        direct_redis_port = CONFIG['haproxy_redis_local_ssl_port'] + port_offset
        sentinel_port = CONFIG['haproxy_sentinel_ssl_port'] + port_offset

        data = redis_obj.run_command(HOSTNAME, direct_redis_port, password, ['INFO', 'replication'])
        if not data:
            print(' 😡 Redis seems down, exiting...')
            is_error = True
            continue

        # We do backups only on slaves.
        if data['role'] == 'master' and not force:
            print()
            print('This is the master for this db. Skipping backup.')
            continue

        now = datetime.datetime.now()-datetime.timedelta(seconds=1)
        # Run BGSAVE
        val = redis_obj.run_command(HOSTNAME, direct_redis_port, password, 'BGSAVE')
        if not val:
            print(' 😡 BGSAVE failed, exiting...')
            is_error = True
            continue

        print('OK')
        backup_ok = False
        count = 30
        # Verify if the backup is done.
        while count > 0:
            last_save = redis_obj.run_command(HOSTNAME, direct_redis_port, password, 'LASTSAVE')
            if last_save and last_save > now:
                print(' ✅ Backup done.')
                backup_ok = True
                break

            time.sleep(1)
            count -= 1

        if not backup_ok:
            print(' 😡 No backup reported by LASTSAVE, exiting...')
            is_error = True
            continue

        # Get slaves from Sentinel to pickup one for upload.
        data = redis_obj.run_command(HOSTNAME, sentinel_port, password, ['SENTINEL SLAVES', 'default'])
        if not data or not len(data):
            print(' 😡 Sentinel seems down or no slaves reported, exiting...')
            is_error = True
            continue

        slaves = []
        for i in data:
            if not i['is_sdown']:
                slaves.append(i['ip'])

        slaves.sort()
        print(f'Slaves available: {slaves}')
        my_ip_address = requests.get('http://169.254.169.254/latest/meta-data/local-ipv4').text
        print(f'My IP address: {my_ip_address}.')
        print()
        # We pick the first IP address of the slaves as one to do the upload from.
        if slaves[0] == my_ip_address or force:
            backup_path = f'/data/{db}/redis/dump.rdb'
            gzip_file(backup_path)

            s3_path = f'redis/{CLUSTER}/{SUBCLUSTER}/{db}/dump-{last_save.strftime("%Y%m%d-%H%M%S")}.rdb.gz'
            upload_to_s3(backup_path+'.gz', s3_path)
        else:
            print(f'Skipping upload, it will be done on {slaves[0]}.')

        print()

    if is_error:
        print('There were some errors above, not creating prometheus metric.')


def gzip_file(src_path):
    """Gzip file."""
    cmd = ['/bin/gzip', '--force', '--keep', src_path]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, err = proc.communicate()
    if proc.returncode != 0:
        print(f'Error gzipping {src_path}: {err.decode()}')
        sys.exit(1)


def upload_to_s3(src_path, s3_path):
    """Upload file to S3."""
    print(f'Uploading {src_path} to s3://{S3_BUCKET}/{s3_path}')
    S3.meta.client.upload_file(src_path, S3_BUCKET, s3_path, ExtraArgs={'ServerSideEncryption': 'AES256'})
    print(' 🌎 Upload done.')


def main():
    """Main."""
    parser = argparse.ArgumentParser(description='Create backup of redis dbs and upload to S3')
    parser.add_argument('--db', '-d', help='backup only the given redis db')
    parser.add_argument('--force', '-f', help='force run backup', action='store_true')
    parser.add_argument('--debug', help='debug mode', action='store_true')
    args = parser.parse_args()

    print(f'>> Backup started at {datetime.datetime.now()}')
    run_backup(args.db, args.debug, args.force)
    print(f'>> Backup finished at {datetime.datetime.now()}')
    print('-' * 50)


if __name__ == '__main__':
    main()
