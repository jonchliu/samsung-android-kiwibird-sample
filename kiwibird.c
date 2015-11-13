/*
 *	Copyright (C) 2015 jonchliu
 *
 *	Test reimplementation of "CROM Service". An official Samsung Android app that allowed the user
 *	to unlock the bootloader of the Chinese-model Galaxy S6 which enabled the installation of Custom ROMS.
 *
 *	The app gathers some phone information such as IMEI, encrypts the data then sends it off to:
 *
 *	https://kwb.secmobilesvc.com:7788/requestToken.kwb
 *
 *	The server responds with a token once the data is validated which the phone then checks to
 *	enable/disable the bootloader unlock.
 *
 *	This sample test sends junk phone data to the server then prints out the token response.
 *	You will need your actual phone IMEI to get a valid unlock token.
 *
 *	This sample needs curl library for server access and openssl library for crypto.
 *	
 *
 *	Compiled with: gcc -Wall -O2 -o kiwibird kiwibird.c -lcrypto -lcurl
 *
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <curl/curl.h>


typedef struct
{
	char cmd;
	char hmacKey[0x20]; /* meant to be random */
	char rand[0x20]; /* meant to be random */
	char model[0x20];
	char imei[0x20];
	char cid[0x20];

} request_msg_t; /* sizeof == 0xA1 */

typedef struct
{
	char encText[0x100]; /* encrypted request_msg_t */
	char hmac[0x20]; /* hmacSHA256 of KWBREQ0001+encText */

} request_token_t; /* sizeof == 0x120 */



/* Samsung Server RSA Public Key Modulus */
static const unsigned char g_pub_mod[0x100] =
{
	0xC3, 0x8F, 0x89, 0x63, 0x1C, 0x32, 0x6B, 0x6E, 0x49, 0xF2, 0x12, 0xDB, 0x60, 0x00, 0x81, 0xB2,
	0x9C, 0xE4, 0x37, 0x54, 0xFE, 0xF4, 0x85, 0xDC, 0xF1, 0xC5, 0x14, 0x30, 0x9C, 0x4C, 0x6A, 0xFB,
	0x35, 0x61, 0xED, 0x5E, 0xC2, 0x76, 0xFE, 0x24, 0x4F, 0xAF, 0x34, 0x15, 0xB3, 0xB2, 0xE4, 0xEE,
	0xB4, 0x11, 0x52, 0xCD, 0xB9, 0x62, 0xEA, 0x1A, 0x41, 0xC4, 0x07, 0xEF, 0x5B, 0x0F, 0x3E, 0x08,
	0x14, 0x94, 0x63, 0xDC, 0xFE, 0x26, 0xAF, 0x63, 0x06, 0x0D, 0x26, 0xEE, 0x5A, 0xB6, 0x4B, 0x30,
	0xEE, 0x6A, 0x8A, 0xC4, 0xB6, 0x90, 0x6D, 0x1F, 0x6F, 0x5D, 0x70, 0x70, 0xA6, 0x1C, 0x3D, 0x73,
	0xC1, 0xF3, 0x56, 0x13, 0xB2, 0x32, 0x75, 0xB7, 0x04, 0xA5, 0x92, 0x91, 0x6C, 0xDE, 0x53, 0x40,
	0x2D, 0xDC, 0x47, 0x9E, 0xF6, 0x93, 0x4F, 0xF8, 0x6C, 0x8F, 0x53, 0x14, 0x61, 0x58, 0x59, 0xB2,
	0x2F, 0x89, 0x00, 0x30, 0x71, 0xEC, 0x48, 0x4D, 0x44, 0x83, 0x4F, 0x8F, 0x35, 0x14, 0x10, 0x57,
	0x80, 0x97, 0x74, 0x00, 0x90, 0x65, 0xF3, 0x30, 0x08, 0x35, 0x37, 0xF6, 0xAB, 0xC2, 0xE6, 0x2A,
	0x0B, 0xF2, 0xA0, 0x52, 0xC5, 0x35, 0x1F, 0x4A, 0x1A, 0x4B, 0xC1, 0x38, 0xE8, 0x23, 0xAF, 0x65,
	0x82, 0x7E, 0x9E, 0xED, 0x7E, 0x0F, 0x40, 0x52, 0xD5, 0x32, 0x85, 0xBC, 0xCE, 0x84, 0x0A, 0x71,
	0x4F, 0x81, 0x9F, 0x52, 0xD5, 0xCA, 0x2A, 0xEA, 0x20, 0xDF, 0xD5, 0x7F, 0x39, 0x45, 0x65, 0x2F,
	0xD7, 0x83, 0x2C, 0x2B, 0xCD, 0xB3, 0xA8, 0x63, 0xD6, 0x4D, 0xF2, 0xEA, 0x77, 0xEA, 0x01, 0xCD,
	0xC7, 0xEA, 0xC9, 0x61, 0x0A, 0xD2, 0x8B, 0xE0, 0x00, 0x3A, 0xF5, 0xFD, 0x8A, 0x93, 0xBA, 0x49,
	0x25, 0xEF, 0x94, 0xCB, 0x52, 0xAB, 0x97, 0x23, 0xC9, 0xBB, 0x2C, 0xF5, 0x09, 0x77, 0x38, 0x1B,
};

/* RSA Public Key Exponent */
static const unsigned char g_pub_exp[3] = { 0x01, 0x00, 0x01 };  


static inline int unknown_padding(void)
{
	unsigned long l;
	while ((l = ERR_get_error()) != 0)
	{
		if (ERR_GET_REASON(l) == RSA_R_UNKNOWN_PADDING_TYPE)
			return 1;
	}

	return 0;
}

/* copied straight from openssl rsa_test, Samsung didn't even bother to change this string */
static const char seed[] = "string to make the random number generator think it has entropy";


size_t pubKeyEncMsg(void *inBuf, size_t size, void *outBuf)
{
	int ret;

	unsigned char *encMsg = outBuf; /* sp+0xC */

	unsigned char ptext[0x100];	/* sp+0x14  */
	unsigned char ctext[0x100];	/* sp+0x114 */
	unsigned char utext[0x100];	/* sp+0x214 */
	char errStr[0x100];		/* sp+0x314 */

	memset(ptext, 0, sizeof(ptext));
	memset(ctext, 0, sizeof(ctext));
	memset(utext, 0, sizeof(utext));

	memcpy(ptext, inBuf, size);

	CRYPTO_set_mem_debug_functions(	&CRYPTO_dbg_malloc, 
					&CRYPTO_dbg_realloc, 
					&CRYPTO_dbg_free, 
					&CRYPTO_dbg_set_options, 
					&CRYPTO_dbg_get_options);

	CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL /*3*/);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON /*1*/);

	RAND_seed(seed, sizeof(seed)); /* apparently needed otherwise OAEP fails */

	RSA *key = RSA_new();

	key->n = BN_bin2bn(g_pub_mod, sizeof(g_pub_mod), key->n);
	key->e = BN_bin2bn(g_pub_exp, sizeof(g_pub_exp), key->e);

	if (RSA_check_key(key) == -1)
	{
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), errStr);
		printf("key is invaild : %s", errStr);
		ret = 0;
		goto exit;
	}

	int num = RSA_public_encrypt(size, ptext, ctext, key, RSA_PKCS1_OAEP_PADDING /*4*/);

	if ((num == -1) && unknown_padding())
	{
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), errStr);
		printf("No OAEP support : %s", errStr);
		ret = -1;
		goto exit;
	}

	memcpy(encMsg, ctext, num);
	ret = num;

exit:
	RSA_free(key);
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	CRYPTO_mem_leaks_fp(stderr);

	return(ret);
}

void show(void *ptr, size_t size, size_t nmemb, void *stream)
{
	unsigned char *data = ptr;
	int i;

	printf("\nsize:0x%lX\n", size*nmemb);

	for(i=0; i<size*nmemb; i++)
	{
		printf("%02X ", data[i]);
		if ((i+1)%16 == 0)
			printf("\n");
	}
}

int main(void)
{
	unsigned char hmac_input[0x10A];
	memset(hmac_input, 0, sizeof(hmac_input));
	memcpy(hmac_input, "KWBREQ0001", 0xA);

	unsigned int hmacLen = 0;
	unsigned char hmac[0x20];
	memset(hmac, 0, sizeof(hmac));

	unsigned char enc[0x100];
	memset(enc, 0, sizeof(enc));

	request_msg_t msg;
	memset(&msg, 0, sizeof(msg));
	msg.cmd = 1;

	int ret = pubKeyEncMsg(&msg, sizeof(msg), enc);
	memcpy(&hmac_input[0xA], enc, ret);

	HMAC(EVP_sha256(), msg.hmacKey, sizeof(msg.hmacKey), hmac_input, sizeof(hmac_input), hmac, &hmacLen);

	request_token_t tok;
	memset(&tok, 0, sizeof(tok));
	memcpy(&tok.encText, enc, ret);
	memcpy(&tok.hmac, hmac, hmacLen);

	CURL *curl;
	CURLcode res;
 
	struct curl_httppost *formpost = NULL;
	struct curl_httppost *lastptr = NULL;
 
	curl_global_init(CURL_GLOBAL_ALL);
 
	curl_formadd(&formpost, &lastptr,
		CURLFORM_COPYNAME, "tokenreq",
		CURLFORM_COPYCONTENTS, tok,
		CURLFORM_END);
 	
	curl = curl_easy_init();
	if (!curl) 
	{
		printf("Failed init\n");
		return -1;
	}

	curl_easy_setopt(curl, CURLOPT_URL, "https://kwb.secmobilesvc.com:7788/requestToken.kwb");
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, show);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
 
	res = curl_easy_perform(curl);
	if(res != CURLE_OK)
	{
		printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
	}

	curl_easy_cleanup(curl);
	curl_formfree(formpost);

	return 0;
}


