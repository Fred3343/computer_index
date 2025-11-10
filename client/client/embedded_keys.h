#ifndef EMBEDDED_KEYS_H
#define EMBEDDED_KEYS_H

#include <stddef.h>

/* 在此内置多把公钥（PEM），key_id 要与 license payload.pub_key_id 一致 */
typedef struct
{
	const char* key_id;  // 对应 license 中的 pub_key_id
	const char* pem;     // PEM 公钥（含 BEGIN/END）
} embedded_key_t;

/* 示例占位（请替换为你的真实公钥；可添加多条） */
static const embedded_key_t g_embedded_keys[] = {
	{
		"ed25519",
		"-----BEGIN PUBLIC KEY-----\n"
		"MCowBQYDK2VwAyEAoghpIaJ89ZN/LgL1Cq6qJu1RcztsthoPytcnkwkm9Fs=\n"
		"-----END PUBLIC KEY-----\n"
	},
	{
		"ed25519-20251110-106c05b6",
		"-----BEGIN PUBLIC KEY-----\n"
		"MCowBQYDK2VwAyEAzX1+5K3hF6vJt9Y8nX5Z2V7y3tG9ifpJaO8InwkrX3zIQ=\n"
		"-----END PUBLIC KEY-----\n"
	},
	{
		"ed25519-20251110-5675f1ed",
		"-----BEGIN PUBLIC KEY-----\n"
		"MCowBQYDK2VwAyEAASaSwom2H5P/B8T27fWrDAn+61w2/Wk5N/D+Bfe7K/g=\n"
		"-----END PUBLIC KEY-----\n"
	},
	{
		"ed25519-20251110-16887685",
		"-----BEGIN PUBLIC KEY-----\n"
		"MCowBQYDK2VwAyEAQT/Ndf9c/a1Vl7mMrZUZ3wimFTItDWP2Om6Ts/dHwq0=\n"
		"-----END PUBLIC KEY-----\n"
	},
	{
		"ed25519-20251110-18326885",
		"-----BEGIN PUBLIC KEY-----\n"
		"MCowBQYDK2VwAyEAY2T2ObDErxn8pTiG6HD8z8r+YkXJiA/KLu342+xtL+E=\n"
		"-----END PUBLIC KEY-----\n"
	},
	{
		"ed25519-20251110-92234349",
		"-----BEGIN PUBLIC KEY-----\n"
		"MCowBQYDK2VwAyEArxQDY4FpqQGYk4IN/nwfhD98TWSBAle2+AZ8jbEyNto=\n"
		"-----END PUBLIC KEY-----\n"
	},

	/* 备份公钥示例
	{
		"KEYID_2025_BACKUP",
		"-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD...\n"
		"-----END PUBLIC KEY-----\n"

	},
	*/
};

static const size_t g_embedded_keys_count =
sizeof(g_embedded_keys) / sizeof(g_embedded_keys[0]);

#endif // EMBEDDED_KEYS_H
