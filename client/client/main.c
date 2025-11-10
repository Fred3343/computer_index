#include "agent.h"
#include <signal.h>
#include <unistd.h>
#include <stdio.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int sig)
{
    (void)sig; g_stop = 1;
}

int main(void)
{
    /* 捕获 Ctrl+C / kill 停止信号 */
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    /* 可留空走默认/环境变量（LIC_SERVER、LOG_LEVEL 等） */
    offline_lic_cfg_t cfg = {
        .server_url = NULL,  // 也可填 "http://112.124.69.70:9091"
        .license_path = NULL,  // 默认: /etc/yourapp/license/license.lic
        .state_path = NULL,  // 默认: /etc/yourapp/license/state.json
        .pubkeys_dir = NULL,  // 默认: /etc/yourapp/license/pubkeys
        .sec_heartbeat = 60,     // 心跳间隔
        .sec_report = 60,    // 指纹上报
        .sec_crl = 600,     // CRL 拉取
        .sec_verify = 600,     // 本地校验
        .log_level = 1,     // 0=DEBUG 1=INFO 2=WARN 3=ERR
        .enforce_initial = 1     // -1 用默认（启用）
    };

    if (offline_lic_agent_start(&cfg) != 0)
    {
        fprintf(stderr, "start agent thread failed\n");
        return 1;
    }

    /* 前台常驻；每 5 秒打印一次状态，Ctrl+C 安全退出 */
    int tick = 0;
    while (!g_stop)
    {
        sleep(1);
        //if (++tick >= 5)
        //{
        //    tick = 0;
        //    offline_lic_status_t st;
        //    if (offline_lic_agent_get_status(&st) == 0)
        //    {
        //        printf("[STAT] run=%d enforce=%d revoked=%d grace=%d exp=%lld msg=%s\n",
        //            st.running, st.enforce, st.revoked, st.in_grace,
        //            st.expires_at, st.last_msg);
        //        fflush(stdout);
        //    }
        //}
    }

    offline_lic_agent_stop();
    offline_lic_agent_join(-1);  // 一直等到线程退出
    return 0;
}
