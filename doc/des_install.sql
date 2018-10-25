DROP FUNCTION IF EXISTS my_des_decrypt;
DROP FUNCTION IF EXISTS my_des_encrypt;

CREATE FUNCTION my_des_decrypt RETURNS string SONAME 'libmysq1_des_udf.so';
CREATE FUNCTION my_des_encrypt RETURNS string SONAME 'libmysq1_des_udf.so';
