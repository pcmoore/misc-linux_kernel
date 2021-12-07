// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * TODO: intro, copyright boilerplate, etc.
 */

/*
 *
 *
 * XXX: audit stash helpers
 *
 *
 */

struct audit_stash *__audit_stash_new(struct audit_buffer *ab,
				      enum audit_data_code code,
				      enum audit_data_type type,
				      u32 flags)
{
	struct audit_stash *stash;
	struct audit_data_def *def;

	if (!ab || code < __AUD_DATA_MIN || code > __AUD_DATA_MAX)
		return ERR_PTR(-EINVAL);

	def = &audit_code_defs[code];
	if (def->type != type)
		return ERR_PTR(-EINVAL);

	stash = audit_stash_alloc(ab);
	if (!stash)
		return ERR_PTR(-ENOMEM);
	stash->def = ddef;
	stash->flags = flags;

	return stash;
}

int __audit_stash_uint(struct audit_buffer *ab, enum audit_data_code code,
		       unsigned int num, u32 flags)
{
	struct audit_stash *stash;

	stash = __audit_stash_new(ab, code, AUD_DTYP_UINT, flags);
	if (IS_ERR(stash))
		return PTR_ERR(stash);
	stash->d.uint = num;
	return 0;
}

int __audit_stash_int(struct audit_buffer *ab, enum audit_data_code code,
		      int num, u32 flags)
{
	struct audit_stash *stash;

	stash = __audit_stash_new(ab, code, AUD_DTYP_INT, flags);
	if (IS_ERR(stash))
		return PTR_ERR(stash);
	stash->d.sint = num;
	return 0;
}

int __audit_stash_opaque(struct audit_buffer *ab, enum audit_data_code code,
			 void *buf, size_t buf_len, u32 flags)
{
	struct audit_stash *stash;

	stash = __audit_stash_new(ab, code, AUD_DTYP_OPAQUE, flags);
	if (IS_ERR(stash))
		return PTR_ERR(stash);

	if (!(flags & AUD_STSFLG_REF)) {
		stash->d.buf = kmemdup(buf, buf_len, ab->gfp);
		if (!stash->d.buf) {
			audit_stash_free(ab, stash);
			return -ENOMEM;
		}
		stash->flags |= AUD_STSFLG_KFREE;
	} else
		stash->d.buf = buf;
	stash->d_len = buf_len;
	return 0;
}

int __audit_stash_string_len(struct audit_buffer *ab, enum audit_data_code code,
			     const char *str, size_t str_len, u32 flags)
{
	struct audit_stash *stash;

	stash = __audit_stash_new(ab, code, AUD_DTYP_STRING, flags);
	if (IS_ERR(stash))
		return PTR_ERR(stash);

	if (!(flags & AUD_STSFLG_REF)) {
		stash->d.string = kmemdup(str, str_len, ab->gfp);
		if (!stash->d.string) {
			audit_stash_free(ab, stash);
			return -ENOMEM;
		}
		stash->flags |= AUD_STSFLG_KFREE;
	} else
		stash->d.string = str;
	stash->d_len = str_len;
	return 0;
}

int __audit_stash_string(struct audit_buffer *ab, enum audit_data_code code,
			 const char *str, u32 flags)
{
	struct audit_stash *stash;

	stash = __audit_stash_new(ab, code, AUD_DTYP_STRING, flags);
	if (IS_ERR(stash))
		return PTR_ERR(stash);

	if (!(flags & AUD_STSFLG_REF)) {
		stash->d.string = kstrdup(str, ab->gfp);
		if (!stash->d.string) {
			audit_stash_free(ab, stash);
			return -ENOMEM;
		}
		stash->flags |= AUD_STSFLG_KFREE;
	} else
		stash->d.string = str;
	stash->d_len = len;
	return 0;
}

int __audit_stash_creds(struct audit_buffer *ab, enum audit_data_code code,
			const struct cred *creds, u32 flags)
{
	struct audit_stash *stash;

	stash = __audit_stash_new(ab, code, AUD_DTYP_CRED,
				  flags | AUD_STSFLG_REF);
	if (IS_ERR(stash))
		return PTR_ERR(stash);
	stash->d.cred = get_cred(creds);
	return 0;
}

int __audit_stash_path(struct audit_buffer *ab, enum audit_data_code code,
		       const struct path *path, u32 flags)
{
	struct audit_stash *stash;

	stash = __audit_stash_new(ab, code, AUD_DTYP_PATH,
				  flags | AUD_STSFLG_REF);
	if (IS_ERR(stash))
		return PTR_ERR(stash);
	stash->d.path = path_get(path);
	return 0;
}

int __audit_stash_ipv4(struct audit_buffer *ab, enum audit_data_code code,
		       const struct sockaddr_in *saddr, u32 flags)
{
	struct audit_stash *stash;

	stash = __audit_stash_new(ab, code, AUD_DTYP_IPV4, flags);
	if (IS_ERR(stash))
		return PTR_ERR(stash);

	if (!(flags & AUD_STSFLG_REF)) {
		stash->d.saddr = kmemdup(saddr, sizeof(*saddr), ab->gfp);
		if (!stash->d.saddr) {
			audit_stash_free(ab, stash);
			return -ENOMEM;
		}
		stash->flags |= AUD_STSFLG_KFREE;
	} else
		stash->d.saddr = saddr;
	stash->d_len = sizeof(*saddr);
	return 0;
}

int __audit_stash_ipv6(struct audit_buffer *ab, enum audit_data_code code,
		       const struct sockaddr_in6 *saddr, u32 flags)
{
	struct audit_stash *stash;

	stash = __audit_stash_new(ab, code, AUD_DTYP_IPV6, flags);
	if (IS_ERR(stash))
		return PTR_ERR(stash);

	if (!(flags & AUD_STSFLG_REF)) {
		stash->d.saddr = kmemdup(saddr, sizeof(*saddr), ab->gfp);
		if (!stash->d.saddr) {
			audit_stash_free(ab, stash);
			return -ENOMEM;
		}
		stash->flags |= AUD_STSFLG_KFREE;
	} else
		stash->d.saddr = saddr;
	stash->d_len = sizeof(*saddr);
	return 0;
}

/* XXX: audit private */
struct audit_data_syscall __audit_stash_syscall(struct audit_buffer *ab)
{
	struct audit_stash *stash;
	struct audit_data_syscall *data;

	stash = __audit_stash_new(ab, AUD_DATA_SYSCALL, AUD_DTYP_SYSCALL,
				  AUD_STSFLG_NONE);
	if (IS_ERR(stash))
		return NULL;
	stash->d_len = sizeof(*data);
	data = &stash->d.aud_syscall;
	ab->ss_syscall = stash;

	return data;
}

/* XXX: audit private */
struct audit_data_uring __audit_stash_uring(struct audit_buffer *ab)
{
	struct audit_stash *stash;
	struct audit_data_uring *data;

	stash = __audit_stash_new(ab, AUD_DATA_URING, AUD_DTYP_URING,
				  AUD_STSFLG_NONE);
	if (IS_ERR(stash))
		return NULL;
	stash->d_len = sizeof(*data);
	data = &stash->d.aud_uring;
	ab->ss_uring = stash;

	return data;
}

int __audit_stash_task(struct audit_buffer *ab, enum audit_data_code code,
		       struct audit_data_task *task, u32 flags)
{
	struct audit_stash *stash;

	if (!(flags & AUD_STSFLG_REF))
		return -EINVAL;

	if (refcount_inc_not_zero(&task->refcount))
		return -EINVAL;

	stash = __audit_stash_new(ab, code, AUD_DTYP_TASK, flags);
	if (IS_ERR(stash)) {
		refcount_dec(&task->refcount);
		return PTR_ERR(stash);
	}

	stash->d.aud_task = task;
	return 0;
}

struct audit_data_task *__audit_stash_task_new(struct audit_buffer *ab,
					       enum audit_data_code code,
					       u32 flags)
{
	int rc;
	struct audit_data_task *data;

	data = kzalloc(sizeof(*data), ab->gfp);
	if (!data)
		return NULL;

	flags = (flags & ~AUD_STSFLG_REF) | AUD_STSFLG_KFREE;
	rc = __audit_stash_task(ab, code, data, flags);
	if (rc)
		kfree(data);

	return rc;
}

/*
 *
 *
 * XXX: audit logging (task/syscall/uring)
 *
 *
 */

/**
 * audit_rc_fixup - fixup syscall return codes
 * @rc: syscall return code
 *
 * We need to fixup the return code in the audit logs if the actual return
 * codes are later going to be fixed by the arch specific signal handlers.
 */
static long audit_return_fixup(long rc)
{
	/*
	 * This is actually a test for:
	 * (rc == ERESTARTSYS ) || (rc == ERESTARTNOINTR) ||
	 * (rc == ERESTARTNOHAND) || (rc == ERESTART_RESTARTBLOCK)
	 *
	 * but is faster than a bunch of ||
	 */
	if (unlikely(rc <= -ERESTARTSYS) && (rc >= -ERESTART_RESTARTBLOCK) &&
	    (rc != -ENOIOCTLCMD))
		return -EINTR;
	return code;
}

int audit_log_task(struct audit_buffer *ab)
{
	return 0;
}

int audit_syscall_entry(struct audit_buffer *ab, int syscall,
			  unsigned long a1, unsigned long a2, unsigned long a3,
			  unsigned long a4, unsigned long a5, unsigned long a6)
{
	struct audit_data_syscall *asc;

	if (!ab)
		return -EINVAL;
	if (WARN(ab->ss_syscall, "audit: syscall stash already exists\n"))
		return -EFAULT;

	asc = __audit_stash_syscall(ab);
	if (!asc)
		return NULL;
	asc->syscall = syscall;
	asc->argv[0] = a1;
	asc->argv[1] = a2;
	asc->argv[2] = a3;
	asc->argv[3] = a4;
	asc->argv[4] = a5;
	asc->argv[5] = a6;

	return 0;
}

int audit_syscall_exit(struct audit_buffer *ab, long rc, bool rc_valid)
{
	struct audit_data_syscall *asc;

	if (!ab)
		return -EINVAL;
	asc = ab->ss_syscall;
	if (WARN(!asc, "audit: syscall stash missing\n"))
		return -EFAULT;

	asc->arch = syscall_get_arch(current);
	asc->personality = current->personality;
	asc->rc = audit_return_fixup(rc);
	asc->rc_valid = rc_valid;

	return 0;
}

/*
 *
 *
 * XXX: audit logging (general/stashes)
 *
 *
 */

/* XXX - example, do we need this? see struct audit_data_common */
int audit_stash_pid(struct audit_buffer *ab, enum audit_data_code code,
		    pid_t pid)
{
	return __audit_log_sint(ab, code, pid);
}

