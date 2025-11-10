#ifndef LICENSE_H
#define LICENSE_H
#include <jansson.h>
#include <openssl/evp.h>
#include <stddef.h>

typedef struct
{
    int ok;                 // 1=通过，0=失败
    int err;                // 非0表示错误码
    char msg[128];          // 简要错误
    long long not_before;
    long long expires_at;
    char license_id[64];    // 证书ID（若有）
    char pub_key_id[64];    // 使用的公钥ID
} lic_result_t;

/* --- Base64URL --- */
char* b64url_encode(const unsigned char* data, size_t len);
int   b64url_decode(const char* in, unsigned char** out, size_t* out_len);

/* --- Ed25519 --- */
int ed25519_sign_pem(const char* sk_pem_path,
    const unsigned char* msg, size_t msg_len,
    unsigned char** sig, size_t* sig_len);

EVP_PKEY* load_pubkey_by_id(const char* pubkeys_dir, const char* key_id); // pk-<id>.pem
EVP_PKEY* load_any_pubkey_try_all(const char* pubkeys_dir);               // 兜底

/* 生成 license 文档（payload+sig），payload 必须不含 sig 字段 */
int license_make_with_sig(json_t* payload, const char* sk_pem_path, json_t** out_doc);

/* 验证 license 文件（验签/验时/验指纹），pubkeys_dir 下存放多把 pk-<id>.pem */
int license_verify_file(const char* license_path, const char* pubkeys_dir,
    lic_result_t* res, int check_fingerprint);

#endif
