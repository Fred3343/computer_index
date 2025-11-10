// offline_license_agent.c
#define _GNU_SOURCE
#include "agent.h"

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <curl/curl.h>
#include <jansson.h>

#include "fp_common.h"   // collect_fingerprint / sha256_of_json_canon
#include "license.h"     // license_verify_file / lic_result_t

/* util.c 中的函数（没有头文件，这里做前置声明） */
int ensure_dir(const char* path);
int json_save_pretty(json_t* obj, const char* path);

#ifdef __cplusplus
extern "C" {
#endif

    /* === 全局一次性初始化 libcurl === */
    static pthread_once_t g_curl_once = PTHREAD_ONCE_INIT;
    static void curl_init_once(void)
    {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    /* ===== 默认值（可被配置/环境变量覆盖） ===== */
    static char SERVER_URL_BUF[256] = "http://112.124.69.70:9091";
    static const char* SERVER_URL = SERVER_URL_BUF;

#include <limits.h>  // 若无 PATH_MAX，可用固定缓冲
    static char LIC_PATH_BUF[512] = "/etc/yourapp/license/license.lic";
    static char STATE_PATH_BUF[512] = "/etc/yourapp/license/state.json";
    static char PUBKEYS_DIR_BUF[512] = "/etc/yourapp/license/pubkeys";

    static const char* LIC_PATH = LIC_PATH_BUF;
    static const char* STATE_PATH = STATE_PATH_BUF;
    static const char* PUBKEYS_DIR = PUBKEYS_DIR_BUF;

    static int SEC_HEARTBEAT = 1;
    static int SEC_REPORT = 10;
    static int SEC_CRL = 3;
    static int SEC_VERIFY = 5;

    enum
    {
        LOG_DEBUG = 0, LOG_INFO = 1, LOG_WARN = 2, LOG_ERR = 3
    };
    static int g_log_level = LOG_INFO;
    static int g_enforce = 1;

#ifndef SAFE_STR
#define SAFE_STR(s) ((s)?(s):"(null)")
#endif

    /* ===== 线程控制 / 状态 ===== */
    static pthread_t g_thr = 0;
    static atomic_int g_running = 0;
    static atomic_int g_stop = 0;

    static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
    static offline_lic_status_t g_status;

    /* ===== 日志 ===== */
    static const char* lvl(int l)
    {
        return l == 0 ? "DEBUG" : l == 1 ? "INFO" : l == 2 ? "WARN" : "ERR";
    }
    static void log_msg(int l, const char* fmt, ...)
    {
        if (l < g_log_level) return;
        time_t t = time(NULL); struct tm tm; localtime_r(&t, &tm);
        char ts[32]; strftime(ts, sizeof(ts), "%F %T", &tm);
        va_list ap; va_start(ap, fmt);
        fprintf(stdout, "%s [%s] ", ts, lvl(l));
        vfprintf(stdout, fmt, ap);
        fputc('\n', stdout); fflush(stdout);
        va_end(ap);
    }

    /* ===== HTTP ===== */
    struct buf
    {
        char* p; size_t n;
    };
    static size_t wr(void* ptr, size_t s, size_t n, void* ud)
    {
        size_t len = s * n; struct buf* b = (struct buf*)ud;
        char* np = (char*)realloc(b->p, b->n + len + 1); if (!np) return 0;
        b->p = np; memcpy(b->p + b->n, ptr, len); b->n += len; b->p[b->n] = '\0'; return len;
    }
    static int http_get(const char* url, long* code, char** out)
    {
        if (out) *out = NULL; if (code) *code = 0;
        CURL* h = curl_easy_init(); if (!h) return -1;
        struct buf b = { 0 };
        curl_easy_setopt(h, CURLOPT_URL, url);
        curl_easy_setopt(h, CURLOPT_TIMEOUT, 8L);
        curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, wr);
        curl_easy_setopt(h, CURLOPT_WRITEDATA, &b);
        CURLcode rc = curl_easy_perform(h);
        if (rc != CURLE_OK)
        {
            curl_easy_cleanup(h); if (b.p) free(b.p); return -1;
        }
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, code);
        curl_easy_cleanup(h);
        if (out) *out = b.p; else free(b.p);
        return 0;
    }
    static int http_post_json(const char* url, const char* json, long* code, char** out)
    {
        if (out) *out = NULL; if (code) *code = 0;
        CURL* h = curl_easy_init(); if (!h) return -1;
        struct buf b = { 0 }; struct curl_slist* hd = NULL;
        hd = curl_slist_append(hd, "Content-Type: application/json");
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, hd);
        curl_easy_setopt(h, CURLOPT_URL, url);
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, json ? json : "");
        curl_easy_setopt(h, CURLOPT_TIMEOUT, 8L);
        curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, wr);
        curl_easy_setopt(h, CURLOPT_WRITEDATA, &b);
        CURLcode rc = curl_easy_perform(h);
        if (rc != CURLE_OK)
        {
            curl_slist_free_all(hd); curl_easy_cleanup(h); if (b.p) free(b.p); return -1;
        }
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, code);
        curl_slist_free_all(hd); curl_easy_cleanup(h);
        if (out) *out = b.p; else free(b.p);
        return 0;
    }

    /* ===== 配置/工具 ===== */
    static void normalize_server(const char* in)
    {
        if (!in || !*in)
        {
            snprintf(SERVER_URL_BUF, sizeof(SERVER_URL_BUF), "http://112.124.69.70:9091"); return;
        }
        if (!strncasecmp(in, "http://", 7) || !strncasecmp(in, "https://", 8))
            snprintf(SERVER_URL_BUF, sizeof(SERVER_URL_BUF), "%s", in);
        else
            snprintf(SERVER_URL_BUF, sizeof(SERVER_URL_BUF), "http://%s:9091", in);
        SERVER_URL = SERVER_URL_BUF;
    }
    static void read_envs(void)
    {
        const char* v;
        if ((v = getenv("LIC_SERVER"))) normalize_server(v);
        if ((v = getenv("LOG_LEVEL")))
        {
            if (!strcasecmp(v, "DEBUG")) g_log_level = LOG_DEBUG;
            else if (!strcasecmp(v, "INFO")) g_log_level = LOG_INFO;
            else if (!strcasecmp(v, "WARN")) g_log_level = LOG_WARN;
            else g_log_level = LOG_ERR;
        }
        if ((v = getenv("HEARTBEAT_SEC")))
        {
            int n = atoi(v); if (n > 0) SEC_HEARTBEAT = n;
        }
        if ((v = getenv("REPORT_SEC")))
        {
            int n = atoi(v); if (n > 0) SEC_REPORT = n;
        }
        if ((v = getenv("CRL_SEC")))
        {
            int n = atoi(v); if (n > 0) SEC_CRL = n;
        }
        if ((v = getenv("VERIFY_SEC")))
        {
            int n = atoi(v); if (n > 0) SEC_VERIFY = n;
        }
    }

    static void load_state(long long* last_ok, long long* first_fail)
    {
        if (last_ok) *last_ok = 0; if (first_fail) *first_fail = 0;
        json_error_t e; json_t* j = json_load_file(STATE_PATH, 0, &e); if (!j) return;
        if (last_ok)    *last_ok = json_integer_value(json_object_get(j, "last_ok"));
        if (first_fail) *first_fail = json_integer_value(json_object_get(j, "first_fail"));
        json_decref(j);
    }
    static void save_state(long long last_ok, long long first_fail)
    {
        ensure_dir("/etc/yourapp"); ensure_dir("/etc/yourapp/license");
        json_t* j = json_pack("{s:I s:I}", "last_ok", (json_int_t)last_ok, "first_fail", (json_int_t)first_fail);
        json_save_pretty(j, STATE_PATH); json_decref(j);
    }

    /* ===== 与服务器交互 ===== */
    static int fetch_policy_enforce(const char* fpr, int* out_enforce)
    {
        if (out_enforce) *out_enforce = 1;
        char url[512]; snprintf(url, sizeof(url), "%s/api/policy?fpr=%s", SERVER_URL, SAFE_STR(fpr));
        long code = 0; char* resp = NULL;
        if (http_get(url, &code, &resp) != 0 || !resp)
        {
            if (resp) free(resp); return -1;
        }
        if (code != 200)
        {
            free(resp); return -1;
        }
        json_error_t e; json_t* doc = json_loads(resp, 0, &e); free(resp); if (!doc) return -1;
        json_t* v = json_object_get(doc, "enforce_license");
        if (v && json_is_boolean(v))
        {
            if (out_enforce) *out_enforce = json_boolean_value(v) ? 1 : 0; json_decref(doc); return 0;
        }
        json_decref(doc); return -1;
    }
    static void report_fpr(const char* fpr)
    {
        char url[512]; snprintf(url, sizeof(url), "%s/api/register", SERVER_URL);
        char body[768];snprintf(body, sizeof(body), "{\"fpr_sha256\":\"%s\",\"hostname\":\"agent\"}", SAFE_STR(fpr));
        long code; char* resp;
        if (http_post_json(url, body, &code, &resp) == 0) log_msg(LOG_DEBUG, "上报指纹响应=%ld", code);
        else log_msg(LOG_WARN, "上报指纹失败");
        if (resp) free(resp);
    }
    static int fetch_license(const char* fpr)
    {
        char url[512]; snprintf(url, sizeof(url), "%s/download?fpr=%s", SERVER_URL, SAFE_STR(fpr));
        long code; char* resp;
        if (http_get(url, &code, &resp) != 0 || !resp)
        {
            log_msg(LOG_WARN, "下载证书失败(HTTP)"); return -1;
        }
        if (code != 200)
        {
            log_msg(LOG_WARN, "下载证书失败(HTTP %ld)", code); free(resp); return -1;
        }
        ensure_dir("/etc/yourapp"); ensure_dir("/etc/yourapp/license");
        FILE* fp = fopen(LIC_PATH, "w"); if (!fp)
        {
            log_msg(LOG_ERR, "写入证书失败: %s", LIC_PATH); free(resp); return -1;
        }
        fputs(resp, fp); fclose(fp); free(resp);
        log_msg(LOG_INFO, "已保存证书到 %s", LIC_PATH);
        return 0;
    }
    static int parse_license_pubkey_id(char out[128])
    {
        json_error_t e; json_t* j = json_load_file(LIC_PATH, 0, &e); if (!j) return -1;
        json_t* v = json_object_get(j, "pub_key_id");
        if (!v || !json_is_string(v))
        {
            json_decref(j); return -1;
        }
        const char* s = json_string_value(v); strncpy(out, s, 127); out[127] = '\0'; json_decref(j); return 0;
    }
    static int read_license_id(char out[129])
    {
        json_error_t e; json_t* j = json_load_file(LIC_PATH, 0, &e); if (!j) return -1;
        json_t* v = json_object_get(j, "license_id");
        if (!v || !json_is_string(v))
        {
            json_decref(j); return -1;
        }
        const char* s = json_string_value(v); strncpy(out, s, 128); out[128] = '\0'; json_decref(j); return 0;
    }
    static int is_revoked_remote(const char* fpr)
    {
        char url[512]; snprintf(url, sizeof(url), "%s/api/crl", SERVER_URL);
        long code; char* resp; if (http_get(url, &code, &resp) != 0 || !resp) return 0;
        if (code != 200)
        {
            free(resp); return 0;
        }
        int hit = 0; json_error_t e; json_t* doc = json_loads(resp, 0, &e); free(resp);
        if (!doc) return 0;
        if (json_is_object(doc))
        {
            json_t* a = json_object_get(doc, "license_ids");
            json_t* b = json_object_get(doc, "fingerprints");
            char lid[129] = { 0 };
            if (a && json_is_array(a) && read_license_id(lid) == 0)
            {
                size_t i, n = json_array_size(a);
                for (i = 0;i < n;i++)
                {
                    json_t* it = json_array_get(a, i);
                    if (json_is_string(it) && strcmp(json_string_value(it), lid) == 0)
                    {
                        hit = 1; break;
                    }
                }
            }
            if (!hit && b && json_is_array(b))
            {
                size_t i, n = json_array_size(b);
                for (i = 0;i < n;i++)
                {
                    json_t* it = json_array_get(b, i);
                    if (json_is_string(it) && strcmp(json_string_value(it), fpr) == 0)
                    {
                        hit = 1; break;
                    }
                }
            }
        }
        else if (json_is_array(doc))
        {
            char lid[129] = { 0 }; if (read_license_id(lid) == 0)
            {
                size_t i, n = json_array_size(doc);
                for (i = 0;i < n;i++)
                {
                    json_t* it = json_array_get(doc, i);
                    if (json_is_string(it) && strcmp(json_string_value(it), lid) == 0)
                    {
                        hit = 1; break;
                    }
                }
            }
        }
        json_decref(doc); return hit;
    }

    /* ===== 应用配置（只做拷贝，不保存外部指针） ===== */
    static void apply_cfg_defaults(const offline_lic_cfg_t* cfg)
    {
        if (cfg && cfg->server_url && cfg->server_url[0]) normalize_server(cfg->server_url);
        else read_envs();

        if (cfg && cfg->license_path && cfg->license_path[0])
        {
            snprintf(LIC_PATH_BUF, sizeof(LIC_PATH_BUF), "%s", cfg->license_path);
        }
        if (cfg && cfg->state_path && cfg->state_path[0])
        {
            snprintf(STATE_PATH_BUF, sizeof(STATE_PATH_BUF), "%s", cfg->state_path);
        }
        if (cfg && cfg->pubkeys_dir && cfg->pubkeys_dir[0])
        {
            snprintf(PUBKEYS_DIR_BUF, sizeof(PUBKEYS_DIR_BUF), "%s", cfg->pubkeys_dir);
        }

        if (cfg && cfg->sec_heartbeat > 0) SEC_HEARTBEAT = cfg->sec_heartbeat;
        if (cfg && cfg->sec_report > 0) SEC_REPORT = cfg->sec_report;
        if (cfg && cfg->sec_crl > 0) SEC_CRL = cfg->sec_crl;
        if (cfg && cfg->sec_verify > 0) SEC_VERIFY = cfg->sec_verify;

        if (cfg && cfg->log_level >= 0)        g_log_level = cfg->log_level;
        if (cfg && cfg->enforce_initial >= 0)  g_enforce = cfg->enforce_initial;
    }

    static void status_set_msg(const char* msg)
    {
        pthread_mutex_lock(&g_mu);
        snprintf(g_status.last_msg, sizeof(g_status.last_msg), "%s", SAFE_STR(msg));
        pthread_mutex_unlock(&g_mu);
    }

    /* ===== 线程体 ===== */
    static void* agent_thread(void* arg)
    {
        /* 复制入参并释放堆内存，彻底避免悬空 */
        offline_lic_cfg_t local_cfg = { 0 };
        if (arg)
        {
            local_cfg = *(const offline_lic_cfg_t*)arg; free(arg); arg = NULL;
        }

        /* 确保 libcurl 只初始化一次（安全） */
        pthread_once(&g_curl_once, curl_init_once);

        apply_cfg_defaults(&local_cfg);
        log_msg(LOG_INFO, "服务器：%s", SAFE_STR(SERVER_URL));

        json_t* fp = NULL;
        if (collect_fingerprint(&fp) != 0 || !fp)
        {
            log_msg(LOG_ERR, "采集指纹失败"); status_set_msg("采集指纹失败");
            atomic_store(&g_running, 0); return NULL;
        }
        char fpr[65];
        if (sha256_of_json_canon(fp, fpr) != 0)
        {
            json_decref(fp);
            log_msg(LOG_ERR, "计算指纹失败"); status_set_msg("计算指纹失败");
            atomic_store(&g_running, 0); return NULL;
        }
        json_decref(fp);
        printf("硬件指纹：%s\n", fpr); fflush(stdout);

        long long last_ok = 0, first_fail = 0; load_state(&last_ok, &first_fail);
        int in_grace = 0, revoked = 0, last_revoked = -1;
        long long expires_at = 0;
        char last_pub_key_id[64] = { 0 };
        char last_license_id[64] = { 0 };

        time_t now = time(NULL), t_beat = now, t_report = now, t_crl = now, t_verify = now, t_policy = now;

        atomic_store(&g_running, 1);
        while (!atomic_load(&g_stop))
        {
            now = time(NULL);

            /* 心跳 */
            if (now >= t_beat)
            {
                log_msg(LOG_INFO, "心跳：运行中（许可启用=%s，宽限=%s，吊销=%s）",
                    g_enforce ? "是" : "否", in_grace ? "是" : "否", revoked ? "是" : "否");
                t_beat = now + SEC_HEARTBEAT;
            }

            /* 上报指纹 */
            if (now >= t_report)
            {
                report_fpr(fpr);
                t_report = now + SEC_REPORT;
            }

            /* 拉取策略 */
            if (now >= t_policy)
            {
                int en = 1;
                if (fetch_policy_enforce(fpr, &en) == 0)
                {
                    if (g_enforce != en)
                    {
                        g_enforce = en;
                        log_msg(LOG_INFO, "服务器策略更新：许可启用 = %s", g_enforce ? "是" : "否");
                        if (!g_enforce)
                        {
                            in_grace = 0; first_fail = 0; save_state(last_ok, first_fail);
                        }
                    }
                }
                else
                {
                    log_msg(LOG_DEBUG, "获取策略失败，沿用上次策略=%s", g_enforce ? "启用" : "停用");
                }
                t_policy = now + SEC_VERIFY;
            }

            /* CRL（仅启用） */
            if (g_enforce && now >= t_crl)
            {
                revoked = is_revoked_remote(fpr) ? 1 : 0;
                if (revoked != last_revoked)
                {
                    log_msg(revoked ? LOG_WARN : LOG_INFO, "CRL 状态变更：%s", revoked ? "已被吊销（license_id/fpr 命中）" : "未吊销");
                    last_revoked = revoked;
                }
                t_crl = now + SEC_CRL;
            }

            /* 本地验证（仅启用） */
            if (g_enforce && now >= t_verify)
            {
                lic_result_t r; memset(&r, 0, sizeof(r));
                int rc = license_verify_file(LIC_PATH, PUBKEYS_DIR, &r, 1);
                if (rc == 0 && r.ok && !revoked)
                {
                    in_grace = 0; last_ok = now; first_fail = 0; save_state(last_ok, first_fail);
                    expires_at = r.expires_at;
                    snprintf(last_pub_key_id, sizeof(last_pub_key_id), "%s", SAFE_STR(r.pub_key_id));
                    snprintf(last_license_id, sizeof(last_license_id), "%s", SAFE_STR(r.license_id));
                    status_set_msg("OK");
                    log_msg(LOG_INFO, "许可证校验通过：key=%s 有效期至=%lld", SAFE_STR(r.pub_key_id), r.expires_at);
                }
                else
                {
                    const char* reason = (rc == 0 ? SAFE_STR(r.msg) : "校验异常");
                    status_set_msg(reason);
                    log_msg(LOG_WARN, "许可证校验失败：err=%d msg=%s", r.err, reason);

                    /* 缺公钥 -> 拉取公钥后复验 */
                    if (r.err == 5)
                    {
                        char kid[128] = { 0 };
                        if (parse_license_pubkey_id(kid) == 0)
                        {
                            log_msg(LOG_INFO, "缺少公钥，尝试拉取 key_id=%s", kid);
                            long code = 0; char* resp = NULL;
                            char url[512]; snprintf(url, sizeof(url), "%s/api/pubkey?key_id=%s", SERVER_URL, kid);
                            if (http_get(url, &code, &resp) == 0 && resp && code == 200)
                            {
                                ensure_dir("/etc/yourapp"); ensure_dir("/etc/yourapp/license"); ensure_dir(PUBKEYS_DIR);
                                char path[512]; snprintf(path, sizeof(path), "%s/pk-%s.pem", PUBKEYS_DIR, kid);
                                FILE* f = fopen(path, "w");
                                if (f)
                                {
                                    fputs(resp, f); fclose(f); log_msg(LOG_INFO, "已保存公钥 %s", path);
                                }
                                free(resp);
                                lic_result_t r2; memset(&r2, 0, sizeof(r2));
                                if (license_verify_file(LIC_PATH, PUBKEYS_DIR, &r2, 1) == 0 && r2.ok && !revoked)
                                {
                                    in_grace = 0; last_ok = now; first_fail = 0; save_state(last_ok, first_fail);
                                    expires_at = r2.expires_at;
                                    snprintf(last_pub_key_id, sizeof(last_pub_key_id), "%s", SAFE_STR(r2.pub_key_id));
                                    snprintf(last_license_id, sizeof(last_license_id), "%s", SAFE_STR(r2.license_id));
                                    status_set_msg("OK");
                                    log_msg(LOG_INFO, "拉取公钥后校验通过：key=%s", SAFE_STR(r2.pub_key_id));
                                    t_verify = now + SEC_VERIFY;
                                    goto next_loop;
                                }
                            }
                            else if (resp)
                            {
                                free(resp);
                            }
                        }
                    }

                    /* 尝试拉证书 */
                    if (fetch_license(fpr) == 0)
                    {
                        lic_result_t r3; memset(&r3, 0, sizeof(r3));
                        if (license_verify_file(LIC_PATH, PUBKEYS_DIR, &r3, 1) == 0 && r3.ok && !revoked)
                        {
                            in_grace = 0; last_ok = now; first_fail = 0; save_state(last_ok, first_fail);
                            expires_at = r3.expires_at;
                            snprintf(last_pub_key_id, sizeof(last_pub_key_id), "%s", SAFE_STR(r3.pub_key_id));
                            snprintf(last_license_id, sizeof(last_license_id), "%s", SAFE_STR(r3.license_id));
                            status_set_msg("OK");
                            log_msg(LOG_INFO, "已拉取新证书并通过校验：key=%s", SAFE_STR(r3.pub_key_id));
                            t_verify = now + SEC_VERIFY;
                            goto next_loop;
                        }
                        else
                        {
                            log_msg(LOG_WARN, "已拉取新证书，但仍未通过：%s", SAFE_STR(r3.msg));
                        }
                    }

                    /* 宽限（30天） */
                    if (first_fail == 0) first_fail = now;
                    long long days = (now - first_fail) / 86400;
                    in_grace = (days <= 30);
                    log_msg(LOG_WARN, "进入/维持宽限期：已用 %lld/30 天（原因：%s%s）", days, reason, revoked ? "；已被吊销" : "");
                    save_state(last_ok, first_fail);
                }
                t_verify = now + SEC_VERIFY;

            next_loop:;
            }

            /* 写状态快照 */
            pthread_mutex_lock(&g_mu);
            g_status.running = 1;
            g_status.enforce = g_enforce;
            g_status.revoked = revoked;
            g_status.in_grace = in_grace;
            g_status.last_ok = last_ok;
            g_status.first_fail = first_fail;
            g_status.expires_at = expires_at;
            snprintf(g_status.license_id, sizeof(g_status.license_id), "%s", last_license_id);
            snprintf(g_status.pub_key_id, sizeof(g_status.pub_key_id), "%s", last_pub_key_id);
            pthread_mutex_unlock(&g_mu);

            struct timespec ts = { 0, 200 * 1000 * 1000 }; nanosleep(&ts, NULL);
        }

        log_msg(LOG_INFO, "退出");
        atomic_store(&g_running, 0);
        return NULL;
    }

    /* ===== 对外接口 ===== */
    int offline_lic_agent_start(const offline_lic_cfg_t* cfg)
    {
        if (atomic_load(&g_running)) return -1;
        memset(&g_status, 0, sizeof(g_status));
        atomic_store(&g_stop, 0);

        pthread_once(&g_curl_once, curl_init_once);

        /* 复制入参到堆内存，传给线程，避免外层栈变量失效 */
        offline_lic_cfg_t* heap_cfg = NULL;
        if (cfg)
        {
            heap_cfg = (offline_lic_cfg_t*)calloc(1, sizeof(*heap_cfg)); if (!heap_cfg) return -2; *heap_cfg = *cfg;
        }

        int rc = pthread_create(&g_thr, NULL, agent_thread, (void*)heap_cfg);
        if (rc != 0)
        {
            if (heap_cfg) free(heap_cfg); return -2;
        }
        return 0;
    }
    void offline_lic_agent_stop(void)
    {
        atomic_store(&g_stop, 1);
    }
    int offline_lic_agent_join(int timeout_ms)
    {
        if (!atomic_load(&g_running)) return -1;
        if (timeout_ms == 0) return -2;
        if (timeout_ms < 0)
        {
            pthread_join(g_thr, NULL); return 0;
        }

        const int step_ms = 50; int waited = 0;
        while (atomic_load(&g_running) && waited < timeout_ms)
        {
            struct timespec ts = { 0, step_ms * 1000 * 1000 }; nanosleep(&ts, NULL); waited += step_ms;
        }
        if (atomic_load(&g_running)) return -3;
        pthread_join(g_thr, NULL); return 0;
    }
    int offline_lic_agent_get_status(offline_lic_status_t* out)
    {
        if (!out) return -1;
        pthread_mutex_lock(&g_mu); *out = g_status; pthread_mutex_unlock(&g_mu);
        return 0;
    }
    int offline_lic_agent_is_running(void)
    {
        return atomic_load(&g_running) ? 1 : 0;
    }

#ifdef __cplusplus
}
#endif
