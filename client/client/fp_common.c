#define _GNU_SOURCE
#include "fp_common.h"
#include <openssl/sha.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>


/* ========== 指纹字段开关（1=纳入指纹，0=不纳入） ========== */
/* 建议：初期只用 machine_id 与 product_uuid，保证相对稳定 */
#define FPR_INCLUDE_BOARD_SERIAL   0   // 主板序列号，很多设备读不到
#define FPR_INCLUDE_MACS           0   // 所有物理网卡 MAC（排序、去重、小写），易变
#define FPR_INCLUDE_ROOT_UUID      1   // 根分区 UUID，重装/格式化会变化

/*
 * 指纹字段说明（纳入/不纳入的影响）：
 * - machine_id     ：安装时生成，镜像克隆可能一致；稳定性较好，唯一性一般。
 * - product_uuid   ：来自 DMI，虚拟机/嵌入式可能空；稳定性较好，唯一性较强。
 * - board_serial   ：主板序列号，许多设备读取不到；可增强唯一性，但可用性欠佳。
 * - macs           ：物理网卡 MAC 列表（排序去重小写）；唯一性强，但更“易变”（换网卡/虚拟网卡影响）。
 * - root_uuid      ：根分区 UUID，重装或更换磁盘会改变；唯一性强，稳定性一般。
 *
 * 生成流程：
 *   1) 采集 → 2) 固定键名写入 JSON → 3) 规范化（排序+紧凑）→ 4) SHA-256 → 64位hex指纹
 */

static char* read_trim_first_line(const char* path)
{
    FILE* f = fopen(path, "r"); if (!f) return NULL;
    char* line = NULL; size_t n = 0; ssize_t len = getline(&line, &n, f); fclose(f);
    if (len <= 0)
    {
        free(line); return NULL;
    }
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' || isspace((unsigned char)line[len - 1]))) line[--len] = '\0';
    return line;
}

static int is_valid_mac(const char* s)
{
    if (!s || strlen(s) != 17) return 0;
    for (int i = 0;i < 17;i++)
    {
        if (i % 3 == 2)
        {
            if (s[i] != ':') return 0;
        }
        else if (!isxdigit((unsigned char)s[i])) return 0;
    } return 1;
}
static int cmp_str(const void* a, const void* b)
{
    const char* const* pa = (const char* const*)a; const char* const* pb = (const char* const*)b;
    return strcmp(*pa, *pb);
}

static json_t* list_macs_json(void)
{
    DIR* d = opendir("/sys/class/net"); if (!d) return json_array();
    size_t cap = 8, cnt = 0; char** arr = calloc(cap, sizeof(char*)); struct dirent* de;
    while ((de = readdir(d)))
    {
        if (de->d_name[0] == '.') continue; if (!strcmp(de->d_name, "lo")) continue;
        char path[512]; snprintf(path, sizeof(path), "/sys/class/net/%s/address", de->d_name);
        char* mac = read_trim_first_line(path); if (!mac) continue;
        for (char* p = mac;*p;++p)*p = (char)tolower((unsigned char)*p);
        if (!is_valid_mac(mac))
        {
            free(mac); continue;
        }
        if (cnt == cap)
        {
            cap *= 2; arr = realloc(arr, cap * sizeof(char*));
        }
        arr[cnt++] = mac;
    } closedir(d);
    if (cnt == 0)
    {
        free(arr); return json_array();
    }
    qsort(arr, cnt, sizeof(char*), cmp_str);
    json_t* ja = json_array();
    for (size_t i = 0;i < cnt;i++)
    {
        if (i > 0 && !strcmp(arr[i], arr[i - 1]))
        {
            free(arr[i]); continue;
        }
        json_array_append_new(ja, json_string(arr[i])); free(arr[i]);
    }
    free(arr); return ja;
}

static char* get_root_uuid(void)
{
    FILE* p = popen("findmnt -no SOURCE /", "r"); if (!p) return NULL;
    char src[256] = { 0 }; if (!fgets(src, sizeof(src), p))
    {
        pclose(p); return NULL;
    } pclose(p);
    size_t len = strlen(src); while (len > 0 && (src[len - 1] == '\n' || src[len - 1] == '\r')) src[--len] = '\0';
    if (len == 0) return NULL;
    char cmd[512]; snprintf(cmd, sizeof(cmd), "lsblk -no UUID '%s'", src);
    p = popen(cmd, "r"); if (!p) return NULL;
    char uuid[128] = { 0 }; if (!fgets(uuid, sizeof(uuid), p))
    {
        pclose(p); return NULL;
    } pclose(p);
    len = strlen(uuid); while (len > 0 && (uuid[len - 1] == '\n' || uuid[len - 1] == '\r')) uuid[--len] = '\0';
    if (len == 0) return NULL; return strdup(uuid);
}


int collect_fingerprint(json_t** out_json)
{
    if (!out_json) return -1;

    // 1) 创建指纹对象
    json_t* obj = json_object();

    // 2) 采集各字段（字符串由调用方分配，我们使用后会 free；jansson 会复制内容）
    char* machine_id = read_trim_first_line("/etc/machine-id");
    char* product_uuid = read_trim_first_line("/sys/class/dmi/id/product_uuid");
    char* board_serial = NULL;
#if FPR_INCLUDE_BOARD_SERIAL
    board_serial = read_trim_first_line("/sys/class/dmi/id/board_serial");
#endif

    char* root_uuid = NULL;
#if FPR_INCLUDE_ROOT_UUID
    root_uuid = get_root_uuid();
#endif

    json_t* macs = NULL;
#if FPR_INCLUDE_MACS
    macs = list_macs_json();  // 已进行排序、去重、小写处理
#endif

    // 3) 固定键名写入 JSON；缺失时写入 JSON null，保证结构稳定
    //    注意：json_string 会拷贝字符串内容，所以后面可以安全 free 本地字符串
    json_object_set_new(obj, "machine_id",
        machine_id ? json_string(machine_id) : json_null());

    json_object_set_new(obj, "product_uuid",
        product_uuid ? json_string(product_uuid) : json_null());

#if FPR_INCLUDE_BOARD_SERIAL
    json_object_set_new(obj, "board_serial",
        board_serial ? json_string(board_serial) : json_null());
#endif

#if FPR_INCLUDE_MACS
    /* 直接把 macs 对象“移交所有权”给 obj；obj 释放时会一并释放 macs */
    json_object_set_new(obj, "macs", macs ? macs : json_array());
    macs = NULL; // 交权后置空，避免后面重复 decref
#else
    /* 未纳入指纹时，释放我们自己持有的引用，避免内存泄漏 */
    if (macs) json_decref(macs);
#endif

#if FPR_INCLUDE_ROOT_UUID
    json_object_set_new(obj, "root_uuid",
        root_uuid ? json_string(root_uuid) : json_null());
#endif

    // 4) 释放临时字符串（jansson 已复制了内容）
    free(machine_id);
    free(product_uuid);
#if FPR_INCLUDE_BOARD_SERIAL
    free(board_serial);
#else
    (void)board_serial; // 避免未使用警告
#endif

#if FPR_INCLUDE_ROOT_UUID
    free(root_uuid);
#else
    (void)root_uuid;
#endif

    // 5) 返回对象（调用方负责在使用完后 json_decref）
    * out_json = obj;
    return 0;
}

char* json_to_canon_buf(json_t* obj, size_t* out_len)
{
    size_t flags = JSON_SORT_KEYS | JSON_COMPACT;
    char* s = json_dumps(obj, flags); if (!s) return NULL;
    if (out_len) *out_len = strlen(s); return s;
}

int sha256_of_json_canon(json_t* obj, char out_hex[65])
{
    if (!obj || !out_hex) return -1;
    size_t n = 0; char* canon = json_to_canon_buf(obj, &n); if (!canon) return -1;
    unsigned char md[SHA256_DIGEST_LENGTH]; SHA256((unsigned char*)canon, n, md); free(canon);
    static const char* hex = "0123456789abcdef";
    for (int i = 0;i < SHA256_DIGEST_LENGTH;i++)
    {
        out_hex[i * 2] = hex[(md[i] >> 4) & 0xF]; out_hex[i * 2 + 1] = hex[md[i] & 0xF];
    }
    out_hex[64] = '\0'; return 0;
}

void lower_inplace(char* s)
{
    if (!s) return; for (;*s;++s)*s = (char)tolower((unsigned char)*s);
}
