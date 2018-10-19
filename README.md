This is an DES CBC PKS decryptor for mysql_udf

Usage:

The 1st parameter is a cyphertext in hex string

The 2nd parameter is a key

mysql> select my_des_decrypt(UNHEX('537CDA02C769F96F4741AB88DB836237F218B39B28644905'), "password");
+---------------------------------------------------------------------------------------+
| my_des_decrypt(UNHEX('537CDA02C769F96F4741AB88DB836237F218B39B28644905'), "password") |
+---------------------------------------------------------------------------------------+
| 500382198812300646                                                                    |
+---------------------------------------------------------------------------------------+
1 row in set (0.00 sec)

Install:
[root@host mysql_des_udf]$ ./configure \
        --with-mysql=@MYSQL_PREFIX@ \
        --with-mysql-config=/usr/bin/mysql_config
[root@host mysql_des_udf]$ make
[root@host mysql_des_udf]$ make install

[root@host mysql_des_udf] mysql < doc/des_install.sql
