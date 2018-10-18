#include <mysql_version.h>

#ifdef STANDARD
	/* STANDARD is defined, don't use any mysql functions */
	#include <stdlib.h>
	#include <stdio.h>
	#include <string.h>
	#ifdef __WIN__
		typedef unsigned __int64 ulonglong;	/* Microsofts 64 bit types */
		typedef __int64 longlong;
	#else
		typedef unsigned long long ulonglong;
		typedef long long longlong;
	#endif /*__WIN__*/
#else
	#include <my_global.h>
	#include <my_sys.h>
	#if defined(MYSQL_SERVER)
		#include <m_string.h>		/* To get strmov() */
	#else
		/* when compiled as standalone */
		#include <string.h>
		#define strmov(a,b) stpcpy(a,b)
		#define bzero(a,b) memset(a,0,b)
	#endif
#endif
#include <mysql.h>
#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <mysql_des_config.h>
#include <des_decrypt_udf.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>



#ifdef HAVE_DLOPEN

#define DES_BLOCK_SIZE 8

void handleErrors(void)
{

}

int encrypt_internal(unsigned char *ciphertext, unsigned char *plaintext, int plaintext_len, unsigned char *key)
{
	EVP_CIPHER_CTX *ctx = NULL;

	int len = 0;

	int ciphertext_len = 0;
	
	unsigned char *iv = (unsigned char *)"12345678";

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) {

		handleErrors();
		return -1;
	}

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	*/
	if(1 != EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv)) {  

		handleErrors();
		return -1;
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {

		handleErrors();
		return -1;
	}
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		handleErrors();
		return -1;
	}
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt_internal(unsigned char *plaintext, unsigned char *ciphertext, int ciphertext_len, unsigned char *key)
{
	EVP_CIPHER_CTX *ctx = NULL;

	int len = 0;

	int plaintext_len = 0;
	
    unsigned char *iv = (unsigned char *)"12345678";

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		handleErrors();
		return -1;
	}

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	*/
	if(1 != EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv)) {
		handleErrors();
		return -1;
	}

	/* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
		handleErrors();
		return -1;
	}

	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
		handleErrors();
		return -1;
	}
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}


EXPORT_API my_bool my_des_decrypt_init(UDF_INIT * initid, UDF_ARGS * args, char * message)
{
	int i = 0;

	if (args->arg_count != 2) {
		sprintf (
			message,
			"\n%s requires two arguments (udf: %s)\n",
			__FUNCTION__, __FUNCTION__
		);
		return false;
	}

	for (i = 1; i < 2; i++) {
		if (!args->args[i] || !args->lengths[i]) {
			sprintf (
				message,
				"%dst argument is missing (udf: %s)\n",
				i + 1, __FUNCTION__
			);

			fprintf (
				stderr,
				"  - %dst Argument:\n"
				"    - type   : %d\n"
				"    - data   : %s\n"
				"    - length : %ld\n",
				i + 1, args->arg_type[i], args->args[i], args->lengths[i]
			);

			return false;
		}

		if (args->arg_type[i] != STRING_RESULT) {
			sprintf (
				message,
				"%dst argument is must string (udf: %s)\n",
				i + 1, __FUNCTION__
			);
			
			return false;
		}
	}

	initid->maybe_null = 1;
	initid->max_length = DES_BLOCK_SIZE * (args->lengths[0] / DES_BLOCK_SIZE) + DES_BLOCK_SIZE;

	if ((initid->ptr = malloc(sizeof(char) * initid->max_length)) == NULL) {
		sprintf (
			message, 
			"Failed Memory allocated (udf: %s)\n",
			__FUNCTION__
		);
		return false;
	}
	memset(initid->ptr, 0, initid->max_length);

	return true;
}

EXPORT_API char* my_des_decrypt(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args, char *result, unsigned long *length,  char *is_null, char *error __attribute__((unused))) 
{	
    //fprintf (stderr, "  - data    : %s (udf: %s:%d)\n", args->args[0], __FILE__, __LINE__);
    //fprintf (stderr, "  - datalen : %u (%zd) (udf: %s:%d)\n", args->lengths[0], strlen ((char *) args->args[0]), __FILE__, __LINE__);
    //fprintf (stderr, "  - key     : %s (udf: %s:%d)\n", args->args[1], __FILE__, __LINE__);
    //fprintf (stderr, "  - keylen  : %u (udf: %s:%d)\n", args->lengths[1], __FILE__, __LINE__);
			  	
	unsigned char *ciphertext = (unsigned char *)(args->args[0]);
	int ciphertext_len = (int)(args->lengths[0]);
	
	unsigned char *key =  (unsigned char *)(args->args[1]);
	
    *is_null = 0;

	int plaintext_len = decrypt_internal(initid->ptr, ciphertext, ciphertext_len, key);
	
	if (plaintext_len < 0) {
        *is_null = 1;
		return NULL;
	}	
	
	result = initid->ptr;
	result[plaintext_len] = '\0';
	*length = (unsigned int)plaintext_len;

	return result;	
				  
}

EXPORT_API void my_des_decrypt_deinit(UDF_INIT * initid __attribute__((unused)))
{
	if(initid->ptr) {
		free(initid->ptr);
		initid->ptr = NULL;
	}
}

#endif /* HAVE_DLOPEN */

#ifdef __cplusplus
}
#endif

