lib_LTLIBRARIES =

AM_CFLAGS = -Wall
AM_LDFLAGS = -module -avoid-version
AM_CPPFLAGS = -I$(top_srcdir)

BUILT_SOURCES = mysql_des_config.h
lib_LTLIBRARIES += mysq1_des_udf.la
mysq1_des_udf_la_SOURCES  = des_decrypt_udf.c
mysq1_des_udf_la_LIBADD   = -lcrypto
mysq1_des_udf_la_CFLAGS   = -DMYSQL_SERVER -DMYSQL_DYNAMIC_PLUGIN
mysq1_des_udf_la_CPPFLAGS = @MYSQL_HEADER@

DISTCLEANFILES = *~
