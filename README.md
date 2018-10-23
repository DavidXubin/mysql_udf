This is an DES CBC PKS decryptor for mysql_udf

Usage:

The 1st parameter is a cyphertext in hex string

The 2nd parameter is a key

The 3rd parameter is IV

Below is just an example, the key is concealed and replaced by 'XXXXXXX', the IV is concealed and replaced by "YYYYYYYY"

mysql> select my_des_decrypt('537CDA02C769F96F4741AB88DB836237F218B39B28644905', "XXXXXXXX", "YYYYYYYY");

+---------------------------------------------------------------------------------------+

| my_des_decrypt('537CDA02C769F96F4741AB88DB836237F218B39B28644905', "XXXXXXXX", "YYYYYYYY") |

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
