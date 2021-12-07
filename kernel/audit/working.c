// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * TODO: intro, copyright boilerplate, etc.
 */

#include "queues.h"

/*
 *
 *
 * XXX: audit data
 *
 *
 */

enum audit_data_code {
	AUD_DATA_NONE = 0,

	AUD_DATA_SYSCALL,
	AUD_DATA_URING,
	AUD_DATA_TASK,

	__AUD_DATA_MAX,
}
#define __AUD_DATA_MIN		AUD_DATA_NONE
#define __AUD_DATA_MAX		AUD_DATA_NONE

enum audit_data_type {
	AUD_DTYP_NONE = 0,
	AUD_DTYP_LEGACY,	/* used for legacy entries only! */
	AUD_DTYP_UINT,
	AUD_DTYP_INT,
	AUD_DTYP_OPAQUE,
	AUD_DTYP_STRING,
	AUD_DTYP_CRED,
	AUD_DTYP_PATH,
	AUD_DTYP_IPV4,
	AUD_DTYP_IPV6,
	AUD_DTYP_SYSCALL,
	AUD_DTYP_URING,
	AUD_DTYP_TASK,
	__AUD_DTYP_MAX,
};

struct audit_data_def {
	const char *name;
	enum audit_data_code code;
	enum audit_data_type type;
	/* XXX: do we want to have an allowed flags mask here? */
}

#define AUD_DATDEF_DECL(C, T, N) \
	[(C)] = { .name = (N), .code = (C), .type = (T), }
struct audit_data_def audit_data_defs[] = {
	AUD_DATDEF_DECL(AUD_DATA_NONE, AUD_DTYP_NONE, "NONE"),
};
