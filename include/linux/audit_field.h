/* SPDX-License-Identifier: GPL-2.0-or-later */
/* audit_field.h -- Audit field API
 *
 * Copyright (c) 2020 Cisco Systems, Inc. <paul@paul-moore.com>
 * All Rights Reserved.
 */

#ifndef _LINUX_AUDIT_FIELD_H_
#define _LINUX_AUDIT_FIELD_H_

/* TODO: we need some comments here on how to use the API properly */

#define A_F_FLG_DEC		0x00000001
#define A_F_FLG_HEX		0x00000002
#define A_F_FLG_NUM_MASK	0x000000ff

void _audit_field_int(struct audit_buffer *ab, const char *name,
		      int value, int flags);
void _audit_field_uint(struct audit_buffer *ab, const char *name,
		       unsigned int value, int flags);

#define A_F_DEF(N,T,M,F,C) \
	static inline void audit_field_##N(struct audit_buffer *ab, T val) \
		{ return M(ab, #N, val, F); }

#define AUDIT_F_DEF_INT(N, F, C) \
	A_F_DEF(A, int, _audit_field_int, F, C)
#define AUDIT_F_DEF_UINT(N, F, C) \
	A_F_DEF(A, unsigned int, _audit_field_uint, F, C)

AUDIT_F_DEF_INT(foo, A_F_FLG_DEC, "integer decimal field example")

#endif
