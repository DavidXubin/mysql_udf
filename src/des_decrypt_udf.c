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

unsigned char *hex2bin(const char *data, int size, int *outlen)
{
    int i = 0;
    int len = 0;
    char char1 = '\0';
    char char2 = '\0';
    unsigned char value = 0;
    unsigned char *out = NULL;

    if (size % 2 != 0) {
        return NULL;
    }

    len = size / 2;
    out = (unsigned char *)malloc(len * sizeof(char) + 1);
    if (out == NULL) {
        return NULL;
    }

    while (i < len) {
        char1 = *data;
        if (char1 >= '0' && char1 <= '9') {
            value = (char1 - '0') << 4;
        }
        else if (char1 >= 'a' && char1 <= 'f') {
            value = (char1 - 'a' + 10) << 4;
        }
        else if (char1 >= 'A' && char1 <= 'F') {
            value = (char1 - 'A' + 10) << 4;
        }
        else {
            free(out);
            return NULL;
        }
        data++;

        char2 = *data;
        if (char2 >= '0' && char2 <= '9') {
            value |= char2 - '0';
        }
        else if (char2 >= 'a' && char2 <= 'f') {
            value |= char2 - 'a' + 10;
        }
        else if (char2 >= 'A' && char2 <= 'F') {
            value |= char2 - 'A' + 10;
        }
        else {
            free(out);
            return NULL;
        }

        data++;
        *(out + i++) = value;
    }
    *(out + i) = '\0';

    if (outlen != NULL) {
        *outlen = i;
    }

    return out;
}

char *bin2hex(unsigned char *data, int size, int *outlen)
{
	int  i = 0;
	int  v = 0;
	char *p = NULL;
	char *buf = NULL;
	char base_char = 'A';

	buf = p = (char *)malloc(size * 2 + 1);
	for (i = 0; i < size; i++) {
		v = data[i] >> 4;
		*p++ = v < 10 ? v + '0' : v - 10 + base_char;

		v = data[i] & 0x0f;
		*p++ = v < 10 ? v + '0' : v - 10 + base_char;
	}

	*p = '\0';
	if (outlen != NULL) {
		*outlen = size * 2;
	}

    return buf;
}


int encrypt_internal(unsigned char *ciphertext, unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv)
{
	EVP_CIPHER_CTX *ctx = NULL;

	int len = 0;

	int ciphertext_len = 0;

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

int decrypt_internal(unsigned char *plaintext, unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv)
{
	EVP_CIPHER_CTX *ctx = NULL;

	int len = 0;

	int plaintext_len = 0;


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
	if (args->arg_count != 3) {
		sprintf (
			message,
			"\n%s requires 3 arguments (udf: %s)\n",
			__FUNCTION__, __FUNCTION__
		);
		return false;
	}

	int i = 0;

	for (i = 0; i < 3; i++) {
		if (!args->args[i] || !args->lengths[i]) {
			sprintf (
				message,
				"%dst argument is missing (udf: %s)\n",
				i + 1, __FUNCTION__
			);

			return false;
		}

		if (args->arg_type[i] != STRING_RESULT) {
			sprintf (
				message,
				"%dst argument must be string (udf: %s)\n",
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
	unsigned char *ciphertext = (unsigned char *)(args->args[0]);
	int ciphertext_len = (int)(args->lengths[0]);

	unsigned char *key = (unsigned char *)(args->args[1]);

	unsigned char *iv = (unsigned char *)(args->args[2]);

	*is_null = 0;

	unsigned char* pCiphertext = hex2bin(ciphertext, ciphertext_len, &ciphertext_len);

	if(pCiphertext == NULL) {
		*is_null = 1;
		return NULL;
	}

	int plaintext_len = decrypt_internal(initid->ptr, pCiphertext, ciphertext_len, key, iv);

	if(plaintext_len < 0) {
        *is_null = 1;

		free(pCiphertext);
		return NULL;
	}

	result = initid->ptr;
	result[plaintext_len] = '\0';
	*length = (unsigned int)plaintext_len;

	free(pCiphertext);

	return result;
}

EXPORT_API void my_des_decrypt_deinit(UDF_INIT * initid __attribute__((unused)))
{
	if(initid->ptr) {
		free(initid->ptr);
		initid->ptr = NULL;
	}
}


EXPORT_API my_bool my_des_encrypt_init(UDF_INIT * initid, UDF_ARGS * args, char * message)
{
	if (args->arg_count != 3) {
		sprintf (
			message,
			"\n%s requires 3 arguments (udf: %s)\n",
			__FUNCTION__, __FUNCTION__
		);
		return false;
	}

	int i = 0;

	for(i = 0; i < 3; i++) {
		if (!args->args[i] || !args->lengths[i]) {
			sprintf (
				message,
				"%dst argument is missing (udf: %s)\n",
				i + 1, __FUNCTION__
			);
			return false;
		}

		if (args->arg_type[i] != STRING_RESULT) {
			sprintf (
				message,
				"%dst argument must be string (udf: %s)\n",
				i + 1, __FUNCTION__
			);
			return false;
		}
	}

	initid->maybe_null = 1;
	initid->max_length = DES_BLOCK_SIZE * (args->lengths[0] / DES_BLOCK_SIZE) + DES_BLOCK_SIZE;

	if((initid->ptr = malloc (sizeof(char) * initid->max_length)) == NULL) {
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

EXPORT_API char* my_des_encrypt(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args, char *result, unsigned long *length,  char *is_null, char *error __attribute__((unused)))
{
	unsigned char *plaintext = (unsigned char *)(args->args[0]);
	int plaintext_len = (int)(args->lengths[0]);

	unsigned char *key = (unsigned char *)(args->args[1]);

	unsigned char *iv = (unsigned char *)(args->args[2]);

	*is_null = 0;

	int ciphertext_len = encrypt_internal(initid->ptr, plaintext, plaintext_len, key, iv);

	if(ciphertext_len < 0) {
		*is_null = 1;
		return NULL;
	}

	char* pCiphertext = bin2hex(initid->ptr, ciphertext_len, &ciphertext_len);
	if(initid->ptr) {
		free(initid->ptr);
	}

	initid->ptr = pCiphertext;

	if(pCiphertext == NULL) {
		*is_null = 1;
		return NULL;
	}

	result = initid->ptr;
	result[ciphertext_len] = '\0';
	*length = (unsigned int)ciphertext_len;

	return result;
}

EXPORT_API void my_des_encrypt_deinit(UDF_INIT * initid __attribute__((unused)))
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

