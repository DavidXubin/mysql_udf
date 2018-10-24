#ifndef DES_DESCRYPT_UDF_h
#define DES_DESCRYPT_UDF_h

#ifdef EXPORT_API
	#undef EXPORT_API
#endif

#if defined _WIN32 || defined __CYGWIN__
	#ifdef DLL_EXPORT
		#define EXPORT_API __declspec(dllexport)
	#else
		#define EXPORT_API __declspec(dllimport)
	#endif
#else
	#if HAVE_VISIBILITY
		#define EXPORT_API __attribute__ ((visibility("default")))
	#else
		#define EXPORT_API
	#endif
#endif

#ifdef true
    #undef true
#endif

#ifndef false
    #undef false
#endif

#define true 0
#define false 1

EXPORT_API my_bool my_des_decrypt_init(UDF_INIT * initid, UDF_ARGS * args, char * message);
EXPORT_API char* my_des_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                char *is_null, char *error);
EXPORT_API void my_des_decrypt_deinit(UDF_INIT * initid);


EXPORT_API my_bool my_des_encrypt_init(UDF_INIT * initid, UDF_ARGS * args, char * message);
EXPORT_API char* my_des_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length,
                char *is_null, char *error);
EXPORT_API void my_des_encrypt_deinit(UDF_INIT * initid);


#endif
