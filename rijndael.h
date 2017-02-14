#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AES_CYPHER_128,
    AES_CYPHER_192,
    AES_CYPHER_256,
} AES_CYPHER_T;

#ifdef _MSC_VER
    #if _MSC_VER >= 1600
        #include <cstdint>
    #else
        typedef __int8              int8_t;
        typedef __int16             int16_t;
        typedef __int32             int32_t;
        typedef __int64             int64_t;
        typedef unsigned __int8     uint8_t;
        typedef unsigned __int16    uint16_t;
        typedef unsigned __int32    uint32_t;
        typedef unsigned __int64    uint64_t;
    #endif
#elif __GNUC__ >= 3
    #include <cstdint>
#endif

int aes_encrypt_ecb(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key);
int aes_decrypt_ecb(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key);
int aes_encrypt_cbc(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv);
int aes_decrypt_cbc(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv);

#ifdef __cplusplus
};
#endif