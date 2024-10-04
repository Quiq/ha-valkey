## Helper scripts

You can set path to CA for your self-signed certificate using `REQUESTS_CA_BUNDLE` variable or even disable ssl verification with `SSL_VERIFY_FALSE` and use example certificates provided in this repo:

```
$ export SSL_VERIFY_FALSE=1
$ ./redis-status.py -c testcluster1 --subcluster valkeydb-mytest
Cluster: testcluster1
Subcluster: valkeydb-mytest
Databases and port offsets: {'default': 0}
Hosts: {'valkeydb-mytest1.testcluster1.example.com': '10.0.7.72', 'valkeydb-mytest2.testcluster1.example.com': '10.0.7.142', 'valkeydb-mytest3.testcluster1.example.com': '10.0.7.202'}

------------------------------------------------------------------------------------------------------------------------------------------------------
Database                 Redis Port     valkeydb-mytest1                    valkeydb-mytest2                    valkeydb-mytest3
                                        10.0.7.72                          10.0.7.142                         10.0.7.202
------------------------------------------------------------------------------------------------------------------------------------------------------
default                  6379           slave                              MASTER                             slave

$ ./redis-commander.py -c testcluster1 --subcluster valkeydb-mytest --db default --command "config get maxmemory"
Cluster: testcluster1
Subcluster: valkeydb-mytest
Databases and port offsets: {'default': 0}
Hosts: ['valkeydb-mytest1.testcluster1.quiq.sh', 'valkeydb-mytest2.testcluster1.quiq.sh', 'valkeydb-mytest3.testcluster1.quiq.sh']

DB: default
- valkeydb-mytest1.testcluster1.quiq.sh:56379 config get maxmemory
[b'maxmemory', b'419430400']
- valkeydb-mytest2.testcluster1.quiq.sh:56379 config get maxmemory
[b'maxmemory', b'419430400']
- valkeydb-mytest3.testcluster1.quiq.sh:56379 config get maxmemory
[b'maxmemory', b'419430400']
```
