/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PPRF_RS_H
#define _LINUX_PPRF_RS_H

#include <linux/types.h>
#include <linux/stddef.h>

/*
 * PPRF RS public API (lightweight):
 * - RS는 (idx, key) 쌍들의 집합으로 구성됩니다.
 * - 플래시의 첫 3개 PEB에 중복 저장되며, 부팅 시 메모리로 로드됩니다.
 * - 실제 PPRF 트리 복구/암복호화 로직은 상위 레이어에서 구현합니다.
 */

#define PPRF_RS_KEY_LEN 32

struct pprf_rs_node {
	u32 idx;
	u8 key[PPRF_RS_KEY_LEN];
};

/* RS 준비 여부 */
bool pprf_rs_is_ready(void);

/* RS에서 최대 max_nodes개의 노드를 out으로 복사. 반환값은 복사된 개수 */
int pprf_rs_get_nodes(struct pprf_rs_node *out, size_t max_nodes);

/* RS 초기화를 강제로 수행(주의: 기존 데이터 덮어쓸 수 있음) */
int pprf_rs_force_init(void);

#endif /* _LINUX_PPRF_RS_H */
