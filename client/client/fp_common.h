#ifndef FP_COMMON_H
#define FP_COMMON_H

#include <jansson.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

	int   collect_fingerprint(json_t** out_json);              // 采集硬件指纹JSON
	int   sha256_of_json_canon(json_t* obj, char out_hex[65]); // 指纹=规范化JSON+SHA256
	char* json_to_canon_buf(json_t* obj, size_t* out_len);     // 规范化（排序+紧凑）字节
	void  lower_inplace(char* s);

#ifdef __cplusplus
}
#endif
#endif
