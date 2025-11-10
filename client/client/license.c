// license.c
#include "license.h"
#include "fp_common.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <time.h>

/* 新增：内置公钥表 */
#include "embedded_keys.h"

static int ends_with(const char* s, const char* suffix)
{
    size_t ls = strlen(s), lt = strlen(suffix); return ls >= lt && !strcmp(s + ls - lt, suffix);
}

/* base64url —— 与原逻辑一致 */
char* b64url_encode(const unsigned char* data, size_t len)
{
    if (!data || !len)
    {
        char* z = (char*)malloc(1); if (z) z[0] = '\0'; return z;
    }
    int outlen = 4 * ((int)(len + 2) / 3);
    unsigned char* b64 = (unsigned char*)malloc(outlen + 1); if (!b64) return NULL;
    int w = EVP_EncodeBlock(b64, data, (int)len); if (w < 0)
    {
        free(b64); return NULL;
    }
    for (int i = 0;i < w;i++)
    {
        if (b64[i] == '+') b64[i] = '-'; else if (b64[i] == '/') b64[i] = '_';
    }
    while (w > 0 && b64[w - 1] == '=') w--;
    char* res = (char*)malloc(w + 1); if (!res)
    {
        free(b64); return NULL;
    }
    memcpy(res, b64, w); res[w] = '\0'; free(b64); return res;
}
int b64url_decode(const char* in, unsigned char** out, size_t* out_len)
{
    if (!in || !out || !out_len) return -1;
    size_t inlen = strlen(in);
    char* b64 = (char*)malloc(inlen + 4 + 1); if (!b64) return -1;
    for (size_t i = 0;i < inlen;i++)
    {
        char c = in[i]; b64[i] = (c == '-') ? '+' : (c == '_') ? '/' : c;
    }
    size_t pad = (4 - (inlen % 4)) % 4; for (size_t i = 0;i < pad;i++) b64[inlen + i] = '=';
    b64[inlen + pad] = '\0';
    size_t buflen = ((inlen + pad) / 4) * 3; unsigned char* buf = (unsigned char*)malloc(buflen); if (!buf)
    {
        free(b64); return -1;
    }
    EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new(); if (!ctx)
    {
        free(b64); free(buf); return -1;
    }
    int outl = 0, tmplen = 0;
    EVP_DecodeInit(ctx);
    if (EVP_DecodeUpdate(ctx, buf, &outl, (unsigned char*)b64, (int)strlen(b64)) < 0)
    {
        EVP_ENCODE_CTX_free(ctx); free(b64); free(buf); return -1;
    }
    if (EVP_DecodeFinal(ctx, buf + outl, &tmplen) < 0)
    {
        EVP_ENCODE_CTX_free(ctx); free(b64); free(buf); return -1;
    }
    EVP_ENCODE_CTX_free(ctx);
    *out_len = outl + tmplen; *out = buf; free(b64); return 0;
}

/* 目录中加载（原有） */
EVP_PKEY* load_pubkey_by_id(const char* pubkeys_dir, const char* key_id)
{
    if (!pubkeys_dir || !key_id) return NULL;
    char path[512]; snprintf(path, sizeof(path), "%s/pk-%s.pem", pubkeys_dir, key_id);
    FILE* fp = fopen(path, "r"); if (!fp) return NULL;
    EVP_PKEY* pk = PEM_read_PUBKEY(fp, NULL, NULL, NULL); fclose(fp);
    return pk;
}
EVP_PKEY* load_any_pubkey_try_all(const char* pubkeys_dir)
{
    DIR* d = opendir(pubkeys_dir); if (!d) return NULL;
    struct dirent* de; EVP_PKEY* pk = NULL;
    while ((de = readdir(d)))
    {
        if (de->d_name[0] == '.') continue;
        if (!ends_with(de->d_name, ".pem")) continue;
        if (strncmp(de->d_name, "pk-", 3) != 0) continue;
        char path[512]; snprintf(path, sizeof(path), "%s/%s", pubkeys_dir, de->d_name);
        FILE* fp = fopen(path, "r"); if (!fp) continue;
        pk = PEM_read_PUBKEY(fp, NULL, NULL, NULL); fclose(fp);
        if (pk) break;
    }
    closedir(d); return pk;
}

/* 内置公钥加载 */
static EVP_PKEY* load_pubkey_from_pem_string(const char* pem)
{
    if (!pem) return NULL;
    BIO* bio = BIO_new_mem_buf((void*)pem, (int)strlen(pem)); if (!bio) return NULL;
    EVP_PKEY* pk = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL); BIO_free(bio); return pk;
}
static EVP_PKEY* load_pubkey_by_id_embedded(const char* key_id)
{
    if (!key_id || g_embedded_keys_count == 0) return NULL;
    for (size_t i = 0;i < g_embedded_keys_count;i++)
    {
        if (g_embedded_keys[i].key_id && 0 == strcmp(g_embedded_keys[i].key_id, key_id))
        {
            EVP_PKEY* pk = load_pubkey_from_pem_string(g_embedded_keys[i].pem);
            if (pk) return pk;
        }
    }
    return NULL;
}
static EVP_PKEY* load_any_pubkey_embedded(void)
{
    for (size_t i = 0;i < g_embedded_keys_count;i++)
    {
        EVP_PKEY* pk = load_pubkey_from_pem_string(g_embedded_keys[i].pem);
        if (pk) return pk;
    }
    return NULL;
}

/* 验证主流程：目录公钥优先，其次内置公钥 */
int license_verify_file(const char* license_path, const char* pubkeys_dir,
    lic_result_t* res, int check_fingerprint)
{
    memset(res, 0, sizeof(*res));
    json_error_t jerr; json_t* doc = json_load_file(license_path, 0, &jerr);
    if (!doc)
    {
        snprintf(res->msg, sizeof(res->msg), "读取证书失败"); res->err = 1; return 0;
    }

    json_t* jsig = json_object_get(doc, "sig");
    if (!jsig || !json_is_string(jsig))
    {
        snprintf(res->msg, sizeof(res->msg), "缺少sig"); res->err = 2; json_decref(doc); return 0;
    }
    const char* sig_b64u = json_string_value(jsig);

    json_t* payload = json_deep_copy(doc); json_object_del(payload, "sig");
    size_t n = 0; char* canon = json_to_canon_buf(payload, &n);
    if (!canon)
    {
        res->err = 3; snprintf(res->msg, sizeof(res->msg), "规范化失败"); json_decref(payload); json_decref(doc); return 0;
    }

    unsigned char* sig = NULL; size_t siglen = 0;
    if (b64url_decode(sig_b64u, &sig, &siglen) != 0)
    {
        res->err = 4; snprintf(res->msg, sizeof(res->msg), "sig解码失败"); free(canon); json_decref(payload); json_decref(doc); return 0;
    }

    const char* kid = NULL; const char* lic_id = NULL; json_t* j;
    if ((j = json_object_get(payload, "pub_key_id")) && json_is_string(j)) kid = json_string_value(j);
    if ((j = json_object_get(payload, "license_id")) && json_is_string(j)) lic_id = json_string_value(j);
    if (kid)    strncpy(res->pub_key_id, kid, sizeof(res->pub_key_id) - 1);
    if (lic_id) strncpy(res->license_id, lic_id, sizeof(res->license_id) - 1);

    EVP_PKEY* pk = NULL;
    if (kid && pubkeys_dir) pk = load_pubkey_by_id(pubkeys_dir, kid);
    if (!pk && pubkeys_dir) pk = load_any_pubkey_try_all(pubkeys_dir);
    if (!pk && kid)         pk = load_pubkey_by_id_embedded(kid);
    if (!pk)                pk = load_any_pubkey_embedded();
    if (!pk)
    {
        res->err = 5; snprintf(res->msg, sizeof(res->msg), "未找到公钥");
        free(sig); free(canon); json_decref(payload); json_decref(doc); return 0;
    }

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    int ok = EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, pk);
    if (ok == 1) ok = EVP_DigestVerify(mctx, sig, siglen, (unsigned char*)canon, n);
    EVP_MD_CTX_free(mctx); EVP_PKEY_free(pk); free(sig);

    if (ok != 1)
    {
        res->err = 6; snprintf(res->msg, sizeof(res->msg), "签名校验失败");
        free(canon); json_decref(payload); json_decref(doc); return 0;
    }

    time_t now = time(NULL); long long nb = 0, exp = 0;
    if ((j = json_object_get(payload, "not_before")) && json_is_integer(j)) nb = json_integer_value(j);
    if ((j = json_object_get(payload, "expires_at")) && json_is_integer(j)) exp = json_integer_value(j);
    res->not_before = nb; res->expires_at = exp;
    const long skew = 300;
    if (now + skew < nb)
    {
        res->err = 7; snprintf(res->msg, sizeof(res->msg), "未到生效时间"); free(canon); json_decref(payload); json_decref(doc); return 0;
    }
    if (exp > 0 && now - skew > exp)
    {
        res->err = 8; snprintf(res->msg, sizeof(res->msg), "证书过期"); free(canon); json_decref(payload); json_decref(doc); return 0;
    }

    if (check_fingerprint)
    {
        json_t* jhw = json_object_get(payload, "hw"); const char* want = NULL;
        if (jhw && json_is_object(jhw))
        {
            j = json_object_get(jhw, "fpr_sha256"); if (j && json_is_string(j)) want = json_string_value(j);
        }
        if (!want)
        {
            res->err = 9; snprintf(res->msg, sizeof(res->msg), "缺少硬件指纹"); free(canon); json_decref(payload); json_decref(doc); return 0;
        }
        char want_lc[65] = { 0 }; strncpy(want_lc, want, 64); lower_inplace(want_lc);

        json_t* fpj = NULL; if (collect_fingerprint(&fpj) != 0 || !fpj)
        {
            res->err = 10; snprintf(res->msg, sizeof(res->msg), "采集指纹失败"); free(canon); json_decref(payload); json_decref(doc); return 0;
        }
        char have[65]; if (sha256_of_json_canon(fpj, have) != 0)
        {
            json_decref(fpj); res->err = 11; snprintf(res->msg, sizeof(res->msg), "计算指纹失败"); free(canon); json_decref(payload); json_decref(doc); return 0;
        }
        json_decref(fpj);
        if (strncmp(want_lc, have, 64) != 0)
        {
            res->err = 12; snprintf(res->msg, sizeof(res->msg), "指纹不匹配"); free(canon); json_decref(payload); json_decref(doc); return 0;
        }
    }

    res->ok = 1; snprintf(res->msg, sizeof(res->msg), "OK");
    free(canon); json_decref(payload); json_decref(doc); return 0;
}
