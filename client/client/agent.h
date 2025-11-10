// offline_license_agent.h
#ifndef AGENT_H
#define AGENT_H

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct
    {
        /* 可选：为空则使用环境变量/默认值 */
        const char* server_url;   // 形如 http://host:port 或 host（自动补端口）

        /* 文件路径（不填则使用默认） */
        const char* license_path; // 默认: /etc/yourapp/license/license.lic
        const char* state_path;   // 默认: /etc/yourapp/license/state.json
        const char* pubkeys_dir;  // 默认: /etc/yourapp/license/pubkeys

        /* 周期（秒），<=0 则使用默认：心跳1s，上报10s，CRL 3s，验证5s */
        int sec_heartbeat;
        int sec_report;
        int sec_crl;
        int sec_verify;

        /* 日志级别：0-DEBUG 1-INFO 2-WARN 3-ERR；<0 使用默认(INFO) */
        int log_level;

        /* 初始是否启用许可校验（若服务端策略可下发，会被覆盖；<0 时使用默认启用） */
        int enforce_initial;

        /* 预留 */
    } offline_lic_cfg_t;

    typedef struct
    {
        int running;        // 线程是否在运行
        int enforce;        // 当前是否启用许可
        int revoked;        // 是否命中吊销
        int in_grace;       // 是否处于宽限期
        long long last_ok;  // 最近一次验证通过的时间戳
        long long first_fail; // 首次失败起点
        long long expires_at; // 证书过期时间（若有）
        char license_id[64];
        char pub_key_id[64];
        char last_msg[128]; // 最近一次验证消息
    } offline_lic_status_t;

    /* 启动：在独立线程内运行。不阻塞。重复启动返回非0；0表示启动成功。 */
    int offline_lic_agent_start(const offline_lic_cfg_t* cfg);

    /* 请求停止线程；非阻塞。 */
    void offline_lic_agent_stop(void);

    /* 等待线程退出（可选）。timeout_ms < 0 一直等；=0 不等；>0 等指定毫秒。 */
    int offline_lic_agent_join(int timeout_ms);

    /* 读取状态（线程安全快照）。返回0成功。 */
    int offline_lic_agent_get_status(offline_lic_status_t* out);

    /* 是否在跑 */
    int offline_lic_agent_is_running(void);

#ifdef __cplusplus
}
#endif

#endif // OFFLINE_LICENSE_AGENT_H
