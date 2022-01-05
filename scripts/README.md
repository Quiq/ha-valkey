## Helper scripts

You can set path to CA for your self-signed certificate using `REQUESTS_CA_BUNDLE` variable or even disable ssl verification with `SSL_VERIFY_FALSE` and use example certificates provided in this repo:

```
$ export SSL_VERIFY_FALSE=1
$ ./redis-status.py -c testcluster1 --subcluster redisdb-mytest
Cluster: testcluster1
Subcluster: redisdb-mytest
Databases and port offsets: {'default': 0}
Hosts: {'redisdb-mytest1.testcluster1.example.com': '10.0.7.72', 'redisdb-mytest2.testcluster1.example.com': '10.0.7.142', 'redisdb-mytest3.testcluster1.example.com': '10.0.7.202'}

------------------------------------------------------------------------------------------------------------------------------------------------------
Database                 Redis Port     redisdb-mytest1                    redisdb-mytest2                    redisdb-mytest3
                                        10.0.7.72                          10.0.7.142                         10.0.7.202
------------------------------------------------------------------------------------------------------------------------------------------------------
default                  6379           slave                              MASTER                             slave

$ ./redis-commander.py -c testcluster1 --subcluster redisdb-mytest --db default --command "config get maxmemory"
Cluster: testcluster1
Subcluster: redisdb-mytest
Databases and port offsets: {'default': 0}
Hosts: ['redisdb-mytest1.testcluster1.quiq.sh', 'redisdb-mytest2.testcluster1.quiq.sh', 'redisdb-mytest3.testcluster1.quiq.sh']

DB: default
- redisdb-mytest1.testcluster1.quiq.sh:56379 config get maxmemory
[b'maxmemory', b'419430400']
- redisdb-mytest2.testcluster1.quiq.sh:56379 config get maxmemory
[b'maxmemory', b'419430400']
- redisdb-mytest3.testcluster1.quiq.sh:56379 config get maxmemory
[b'maxmemory', b'419430400']
```
