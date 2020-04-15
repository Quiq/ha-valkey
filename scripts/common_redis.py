"""Common redis functions."""
import os
import pprint
import sys

import redis
import yaml

try:
    from ansible.parsing.vault import VaultLib, VaultSecret
except ModuleNotFoundError:
    pass

# Timeout in sec for haproxy socket and redis connection.
TIMEOUT = 5

if 'REQUESTS_CA_BUNDLE' not in os.environ:
    os.environ['REQUESTS_CA_BUNDLE'] = '/etc/ssl/certs/ca-certificates.crt'

# It makes it possible to run this script from any directory.
rel_path = os.path.dirname(os.path.realpath(__file__)) + '/'
config_files = {
    'ANSIBLE_VAULT_PASS': os.path.expanduser('~') + '/.ssh/.vault_pass.txt',
    'REDIS_CONFIG': rel_path+'../roles/redisdb/tasks/config.yml',
    'REDIS_SECRETS': rel_path+'../roles/redisdb/vars/main.yml',
    'TLS_CA_CERTS': os.environ['REQUESTS_CA_BUNDLE'],
    'TLS_CERT': rel_path+'../roles/redisdb/files/example.crt',
    'TLS_CERT_KEY': rel_path+'../roles/redisdb/files/example.key',
}


def read_redis_configs(debug):
    """Read redis config, decrypt secrets."""
    # At first detect the file paths so the script can be run on the laptop or remote with copying files.
    for k, v in config_files.items():
        if os.path.exists(v):
            continue

        if os.path.exists(os.path.basename(v)):
            config_files[k] = (v)
        elif k == 'ANSIBLE_VAULT_PASS':
            config_files['ANSIBLE_VAULT_PASS'] = False
            continue
        else:
            print(f'Config file {k} is not found neither at {v} nor in the same dir.')
            sys.exit(1)

    # Read redis config.
    with open(config_files['REDIS_CONFIG'], 'r') as config_file:
        config = yaml.safe_load(config_file)

    data = open(config_files['REDIS_SECRETS'], 'r').read()

    # Decrypt secrets with ansible vault secret (if set).
    if config_files['ANSIBLE_VAULT_PASS']:
        secret = open(config_files['ANSIBLE_VAULT_PASS'], 'r').read().strip().encode()
        vault = VaultLib([('', VaultSecret(secret))])
        data = vault.decrypt(data)

    secrets = yaml.safe_load(data)['secrets']

    if debug:
        pprint.pprint(config)
        pprint.pprint(secrets)

    return config_files, config, secrets


class Redis:
    """Redis class."""

    def __init__(self, debug, verbose=True, timeout=TIMEOUT):
        self.debug = debug
        self.verbose = verbose
        self.timeout = timeout

    def _engine(self, port):
        """Describe engine."""
        engine = 'redis'
        if port >= 16379 and port <= 16479:
            engine = 'sentinel'

        return engine

    def get_client(self, host, port, password):
        """Return client."""
        try:
            r = redis.Redis(host=host, port=port, password=password, socket_timeout=self.timeout,
                            socket_connect_timeout=self.timeout, ssl=True, ssl_ca_certs=config_files['TLS_CA_CERTS'])
            r.ping()
        except (redis.exceptions.ConnectionError, redis.exceptions.ResponseError, redis.exceptions.TimeoutError) as err:
            if self.verbose or self.debug:
                print(f'WARN: {self._engine(port)} error from {host}:{port}: {err}')

            return None

        return r

    def run_command(self, host, port, password, cmd):
        """Run command on Redis or Sentinel."""
        if self.verbose or self.debug:
            print(f'- {host}:{port} {cmd}')

        try:
            r = self.get_client(host, port, password)
            if not r:
                return None

            if type(cmd) == list:
                info = r.execute_command(cmd[0], cmd[1])
            elif cmd.upper().startswith('CONFIG SET'):
                data = cmd.split()
                values = data[3:]
                info = r.config_set(data[2], ' '.join(values))
            else:
                info = r.execute_command(cmd)
        except (redis.exceptions.ConnectionError, redis.exceptions.ResponseError, redis.exceptions.TimeoutError) as err:
            if self.verbose or self.debug:
                print(f'WARN: {self._engine(port)} error from {host}:{port}: {err}')

            return None

        if self.debug:
            pprint.pprint(info)

        return info


def check_arguments(args, config_files, config, secrets, db_arg_check=True):
    """Check arguments passed to the scripts."""
    if args.cluster not in config['instances']:
        print('ERROR: no such cluster defined in [instances] section of the config file.')
        print(f'Check {config_files["REDIS_CONFIG"]}')
        sys.exit(1)

    if args.cluster not in config['services']:
        print('ERROR: no such cluster defined in [services] section of the config file.')
        print(f'Check {config_files["REDIS_CONFIG"]}')
        sys.exit(1)

    if args.cluster not in secrets:
        print('ERROR: no such cluster defined in the password file.')
        print(f'Check {config_files["REDIS_SECRETS"]}')
        sys.exit(1)

    subclusters = {args.subcluster: ''}
    if hasattr(args, 'target_subcluster'):
        if args.subcluster == args.target_subcluster:
            print('ERROR: subcluster and target subcluster cannot be the same.')
            sys.exit(1)

        if args.target_subcluster:
            subclusters[args.target_subcluster] = 'target '

    for subcluster, descr in subclusters.items():
        if subcluster not in config['instances'][args.cluster]:
            print(f'ERROR: no such {descr}subcluster defined for "{args.cluster}" cluster in [instances] section of the config file.')
            print(f'Check {config_files["REDIS_CONFIG"]}')
            sys.exit(1)

        if subcluster not in config['services'][args.cluster]:
            print(f'ERROR: no such {descr}subcluster defined for "{args.cluster}" cluster in [services] section of the config file.')
            print(f'Check {config_files["REDIS_CONFIG"]}')
            sys.exit(1)

        if subcluster not in secrets[args.cluster]:
            print(f'ERROR: no such {descr}subcluster defined for "{args.cluster}" cluster in the password file.')
            print(f'Check {config_files["REDIS_SECRETS"]}')
            sys.exit(1)

        if not db_arg_check:
            continue

        if args.db not in config['services'][args.cluster][subcluster]:
            print(f'ERROR: no such db defined for "{args.cluster}" cluster and "{subcluster}" {descr}subcluster in [services] section of the config file.')
            print(f'Check {config_files["REDIS_CONFIG"]}')
            sys.exit(1)

        if args.db not in secrets[args.cluster][subcluster]:
            print(f'ERROR: no such db defined for "{args.cluster}" cluster and "{subcluster}" {descr}subcluster in the password file.')
            print(f'Check {config_files["REDIS_SECRETS"]}')
            sys.exit(1)
