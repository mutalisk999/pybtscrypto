#include "Python.h"

#include "secp256k1.h"
#include "util.h"

#include "city.hpp"
#include "uint128.hpp"


#define DEBUG_ASSERT(cond) \
if(!(cond)) \
{ \
	fprintf(stderr, "Assert: %s | Function: %s\n", #cond, __FUNCTION__); \
	assert(0); \
}

static secp256k1_context_t* secp256k1_get_context() {
	static secp256k1_context_t* g_secp256k1_ctx = NULL;
    if(!g_secp256k1_ctx)
    	g_secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_RANGEPROOF | SECP256K1_CONTEXT_COMMIT);
    return g_secp256k1_ctx;
}

//获取公钥
static void secp256k1_get_public_key(const unsigned char* priv_key, int priv_key_len, int compressed, unsigned char* pub_key, int* pub_key_len_ptr) {
 	DEBUG_ASSERT(priv_key != NULL);
 	DEBUG_ASSERT(pub_key != NULL);
 	DEBUG_ASSERT(pub_key_len_ptr != NULL);
 	DEBUG_ASSERT(priv_key_len == 32);
 	DEBUG_ASSERT(secp256k1_ec_pubkey_create(secp256k1_get_context(), pub_key, pub_key_len_ptr, priv_key, compressed) != 0);
 	DEBUG_ASSERT( (compressed != 0) ? (*pub_key_len_ptr == 33) : (*pub_key_len_ptr == 65) );
}

static PyObject* secp256k1_get_public_key_wrapper(PyObject *self, PyObject *args) {
	char* priv_key;
	int priv_key_len;
	int compressed;
	
	char pub_key_data[65];
	char* pub_key = pub_key_data;
	int pub_key_len;
		
	PyArg_ParseTuple(args, "s#i" , &priv_key, &priv_key_len, &compressed);
	secp256k1_get_public_key((const unsigned char*)priv_key, priv_key_len, compressed, (unsigned char*)pub_key, &pub_key_len);
	PyObject* resultObject = Py_BuildValue("s#", pub_key, pub_key_len);
	return resultObject;
}

static int extended_nonce_function(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, unsigned int attempt, const void *data) {
    unsigned int* extra = (unsigned int*) data;
    (*extra)++;
    return secp256k1_nonce_function_default(nonce32, msg32, key32, *extra, nullptr);
}

static bool is_canonical(unsigned char* c) {
	return !(c[1] & 0x80)
		&& !(c[1] == 0 && !(c[2] & 0x80))
		&& !(c[33] & 0x80)
		&& !(c[33] == 0 && !(c[34] & 0x80));
}

//对32个字节的数据流做压缩签名
static int secp256k1_sign_compact(const unsigned char* priv_key, int priv_key_len, const unsigned char* origin_data, int origin_data_len, 
		unsigned char* signed_data, int* signed_data_len_ptr) {
	DEBUG_ASSERT(priv_key != NULL);
	DEBUG_ASSERT(origin_data != NULL);
	DEBUG_ASSERT(signed_data != NULL);
	DEBUG_ASSERT(signed_data_len_ptr != NULL);
	DEBUG_ASSERT(priv_key_len == 32);
	DEBUG_ASSERT(origin_data_len == 32);
	
	int recid;
	unsigned int counter = 0;
	
	do {
		DEBUG_ASSERT(secp256k1_ecdsa_sign_compact(secp256k1_get_context(), origin_data, signed_data+1, priv_key, extended_nonce_function, &counter, &recid));
	} while(!is_canonical(signed_data));
	
	signed_data[0] = 27 + 4 + recid;
	*signed_data_len_ptr = 65;
	return 1;
}

static PyObject* secp256k1_sign_compact_wrapper(PyObject *self, PyObject *args) {
	char* priv_key;
	int priv_key_len;
	char* origin_data;
	int origin_data_len;
	char signed_data[64];
	int signed_data_len;
	
	PyArg_ParseTuple(args, "s#s#" , &priv_key, &priv_key_len, &origin_data, &origin_data_len);
	secp256k1_sign_compact((const unsigned char*)priv_key, priv_key_len, 
		(const unsigned char*)origin_data, origin_data_len, 
		(unsigned char*)signed_data, &signed_data_len);
	PyObject* resultObject = Py_BuildValue("s#", signed_data, signed_data_len);
	return resultObject;
}

//对32个字节的数据流以及压缩签名推算压缩公钥
static int secp256k1_get_pubkey_compact(const unsigned char* origin_data, int origin_data_len, const unsigned char* signed_data, int signed_data_len,
		unsigned char* pub_key, int* pub_key_len_ptr) {
	DEBUG_ASSERT(origin_data != NULL);
	DEBUG_ASSERT(signed_data != NULL);
	DEBUG_ASSERT(pub_key != NULL);
	DEBUG_ASSERT(pub_key_len_ptr != NULL);			
	DEBUG_ASSERT(origin_data_len == 32);
	DEBUG_ASSERT(signed_data_len == 65);
		
	DEBUG_ASSERT(signed_data[0] >= 27 && signed_data[0] < 35);
	
	DEBUG_ASSERT(secp256k1_ecdsa_recover_compact(secp256k1_get_context(), origin_data, signed_data+1, pub_key, pub_key_len_ptr, 1, (signed_data[0] - 27) & 3));
	if(*pub_key_len_ptr != 33)
		return 0;
	
	return 1;
}

static PyObject* secp256k1_get_pubkey_compact_wrapper(PyObject *self, PyObject *args) {
	char* origin_data;
	int origin_data_len;
	char* signed_data;
	int signed_data_len;
	char pub_key[64];
	int pub_key_len;
	
	PyArg_ParseTuple(args, "s#s#" , &origin_data, &origin_data_len, &signed_data, &signed_data_len);
	secp256k1_get_pubkey_compact((const unsigned char*)origin_data, origin_data_len, 
		(const unsigned char*)signed_data, signed_data_len, 
		(unsigned char*)pub_key, &pub_key_len);
	PyObject* resultObject = Py_BuildValue("s#", pub_key, pub_key_len);
	return resultObject;
}

//fc库的cityhash
static PyObject* cityhash128_crc_wrapper(PyObject *self, PyObject *args) {
	char* plain_text;
	int plain_text_len;
	char hash_text[64];
	int hash_text_len = sizeof(uint128_t)/sizeof(uint8_t);
	
	PyArg_ParseTuple(args, "s#" , &plain_text, &plain_text_len);

#ifdef __SSE4_2__
	uint128_t hash_value = city_hash_crc_128(plain_text, plain_text_len);
#else
	uint128_t hash_value = city_hash128(plain_text, plain_text_len);
#endif
	
	hash_text[0] = hash_value.hi & (uint64_t)0xFF;
	hash_text[1] = (hash_value.hi & ((uint64_t)0xFF << 8)) >> 8;
	hash_text[2] = (hash_value.hi & ((uint64_t)0xFF << 16)) >> 16;
	hash_text[3] = (hash_value.hi & ((uint64_t)0xFF << 24)) >> 24;
	hash_text[4] = (hash_value.hi & ((uint64_t)0xFF << 32)) >> 32;
	hash_text[5] = (hash_value.hi & ((uint64_t)0xFF << 40)) >> 40;
	hash_text[6] = (hash_value.hi & ((uint64_t)0xFF << 48)) >> 48;
	hash_text[7] = (hash_value.hi & ((uint64_t)0xFF << 56)) >> 56;
	
	hash_text[8] =  hash_value.hi & (uint64_t)0xFF;                   
	hash_text[9] =  (hash_value.lo & ((uint64_t)0xFF << 8)) >> 8;     
	hash_text[10] = (hash_value.lo & ((uint64_t)0xFF << 16)) >> 16;   
	hash_text[11] = (hash_value.lo & ((uint64_t)0xFF << 24)) >> 24;   
	hash_text[12] = (hash_value.lo & ((uint64_t)0xFF << 32)) >> 32;   
	hash_text[13] = (hash_value.lo & ((uint64_t)0xFF << 40)) >> 40;   
	hash_text[14] = (hash_value.lo & ((uint64_t)0xFF << 48)) >> 48;   
	hash_text[15] = (hash_value.lo & ((uint64_t)0xFF << 56)) >> 56;   
	
	PyObject* resultObject = Py_BuildValue("s#", hash_text, hash_text_len);
	return resultObject;
}

static PyMethodDef crypto_methods[] = {
	{"secp256k1_get_public_key" , secp256k1_get_public_key_wrapper, METH_VARARGS, "secp256k1_get_public_key(priv_key, compressed)"},
	{"secp256k1_sign_compact", secp256k1_sign_compact_wrapper, METH_VARARGS, "secp256k1_sign_compact(priv_key, origin_data)"},
	{"secp256k1_get_pubkey_compact", secp256k1_get_pubkey_compact_wrapper, METH_VARARGS, "secp256k1_get_pubkey_compact(origin_data, signed_data)"},
	{"cityhash128_crc", cityhash128_crc_wrapper, METH_VARARGS, "cityhash128_crc(plain_text)"},
	{NULL, NULL, 0, NULL}
};

extern "C" {
	void initpybtscrypto(void) {
		Py_InitModule("pybtscrypto", crypto_methods);
	}
}