/* SPDX-License-Identifier: GPL-2.0-or-later */
/* audit_field.c -- Audit field API
 *
 * Copyright (c) 2020 Cisco Systems, Inc. <paul@paul-moore.com>
 * All Rights Reserved.
 */

#include <linux/audit.h>
#include <linux/audit_field.h>

void _audit_field_int(struct audit_buffer *ab, const char *name,
		      int value, int flags)
{
	switch (flags & A_F_FLG_NUM_MASK) {
	case A_F_FLG_HEX:
		audit_log_format(ab, " %s=%x", name, value);
	/* fallthrough */
	case A_F_FLG_DEC:
	default:
		audit_log_format(ab, " %s=%d", name, value);
	}
}

void _audit_field_uint(struct audit_buffer *ab, const char *name,
		       unsigned int value, int flags)
{
	switch (flags & A_F_FLG_NUM_MASK) {
	case A_F_FLG_HEX:
		audit_log_format(ab, " %s=%x", name, value);
	/* fallthrough */
	case A_F_FLG_DEC:
	default:
		audit_log_format(ab, " %s=%u", name, value);
	}
}
