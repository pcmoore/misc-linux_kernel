// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * TODO: intro, copyright boilerplate, etc.
 */

/*
 *
 *
 * XXX: audit timestamp
 *
 *
 */

struct audit_timestamp {
	struct timespec64 time;
	unsigned int serial;
};

/*
 *
 *
 * XXX: audit string
 *
 *
 */

struct audit_str {
	size_t len;
	char str[];
}

struct audit_str *audit_str_alloc(size_t len, gfp_t gfp)
{
	struct audit_str *astr;

	astr = kmalloc(sizeof(*astr) + len + 1, gfp);
	if (!astr)
		return NULL;
	astr->len = len;

	return astr;
}

void audit_str_free(struct audit_str *astr)
{
	kfree(astr);
}

struct audit_str audit_str_new(const char *str, gfp_t gfp)
{
	size_t len;
	struct audit_str *astr;

	if (!str)
		return NULL;
	len = strlen(str);

	astr = audit_str_alloc(len, gfp);
	if (!astr)
		return NULL;
	memcpy(astr->str, str, len);
	astr->buf[len] = '\0';

	return astr;
}

/*
 *
 *
 * XXX: audit key
 *
 *
 */

struct audit_key {
	refcount_t refcount;
	struct audit_str *name;
	struct audit_key_db *db;
	struct list_head list;
	struct rcu_head rcu;
};

struct audit_key_db {
	struct list_head list;
	spinlock_t lock;
}

int audit_key_alloc(struct audit_key_db *db, const char *name, gfp_t gfp)
{
	struct audit_key *key = NULL;

	key = kmalloc(sizeof(*key), gfp);
	if (!key)
		return -ENOMEM;

	key->name = audit_str_new(name, gfp);
	if (!key->name)
		goto err;
	key->recount = ATOMIC_INIT(1);
	key->db = db;
	INIT_LIST_HEAD(&key->list);

	spin_lock(&db->lock);
	list_add_rcu(&key->list, &db->list);
	spin_unlock(&db->lock);

	return 0;

err:
	if (key)
		audit_str_free(key->name);
	kfree(key);
}

void __audit_key_free(struct rcu_head *entry)
{
	struct audit_key *key = container_of(entry, struct audit_key, rcu);

	audit_str_free(key->name);
	kfree(key);
}

static struct audit_key *__audit_key_get(struct audit_key *key)
{
	return (refcount_inc_not_zero(&key->refcount) ? key : NULL);
}

struct audit_key *audit_key_get(struct audit_key *key)
{
	struct audit_key *k;

	if (!key)
		return NULL;

	rcu_read_lock();
	k = __audit_key_get(key);
	rcu_read_unlock();

	return k;
}

void audit_key_put(struct audit_key *key)
{
	if (!key)
		return;

	if (refcount_dec_and_test(key)) {
		spin_lock(&key->db->lock);
		list_del_rcu(&key->list);
		spin_unlock(&key->db->lock);

		call_rcu(&key->rcu, __audit_key_free);
	}
}

struct audit_key *audit_key_find(struct audit_key_db *db, const char *name)
{
	struct audit_key *i;
	struct audit_key *key;

	if (!name)
		return NULL;

	key = NULL;
	rcu_read_lock();
	list_for_each_entry_rcu(i, &db->list, list) {
		if (refcount_read(i->refcount) && !strcmp(i->name->str, name)) {
			key = __audit_key_get(i);
			if (key)
				break;
		}
	}
	rcu_read_unlock();
	return key;
}

/*
 *
 *
 * XXX: audit buffer
 *
 *
 */

struct audit_data_syscall {
	/* syscall info */
	int arch;
	int syscall;
	unsigned long personality;
	long rc;
	bool rc_valid;
	unsigned long argv[6];
};

struct audit_data_uring {
	/* uring info */
	int uring_op;
	long rc;
	bool rc_valid;
};

struct audit_data_task {
	/* constant data for a given task_struct */

	/* audit loginid and sessionid */
	kuid_t auid;
	unsigned int sessionid;

	/* process info */
	pid_t ppid;
	pid_t tgid;
	struct tty_struct *tty;
	char comm[TASK_COMM_LEN];
	const struct file *exec_file;
	struct audit_str *cmdline;

	/* refcount */
	refcount_t refcount;
};

struct audit_data_cred {
	/* credential information*/
	/* NOTE: we capture the secctx as it could change underneath us */
	struct cred *cred;
	char *secctx;
}

struct audit_data_path {
	/* file information */
	int type;

	dev_t dev;
	dev_t rdev;
	unsigned long inode;

	kuid_t uid;
	kgid_t gid;
	umode_t mode;
	char *secctx;

	audit_str *path;
	size_t path_len;
}

struct audit_data_LEFTOVERS_THAT_NEED_A_PLACE_TO_LIVE {

	/* XXX: DO NOT USE THIS STRUCT, just a reminder of untracked info */

	/* file info */
	int fd[2];
	struct path *cwd;
	int path_count;
	struct list_head paths;


};

struct audit_stash {
	struct list_head list;
#define AUD_STSFLG_NONE			0x00000000
#define AUD_STSFLG_STASHFREE		0x00000001
#define AUD_STSFLG_KFREE		0x00000002
#define AUD_STSFLG_REF			0x00000004
#define AUD_STSFLG_UNSAFEDATA		0x00000010
	u32 flags;
	const struct audit_data_def *def;
	size_t d_len;
	union {
		struct audit_data_syscall aud_syscall;
		struct audit_data_uring aud_uring;
		struct audit_data_task *aud_task;
		int sint;
		unsigned int uint;
		const char *string;
		const struct cred *cred;
		const struct path *path;
		const struct sockaddr_storage *saddr;
		void *buf;
	} d;
};

struct audit_buffer {
	/* alloc flag */
	gfp_t gfp;

	/* general buffer info */
	int type;
	struct audit_timestamp tstamp;
	struct audit_key *key;

	/* direct ptrs to special stashes */
	struct audit_stash *ss_syscall;
	struct audit_stash *ss_uring;

	/* stashes */
	unsigned int s_cnt_ab;
	unsigned int s_cnt;
	struct list_head s_list;
	struct audit_stash stashes[];
};

/*
 *
 *
 * XXX: audit buffer/stash mgmt
 *
 *
 */

static struct kmem_cache *audit_buffer_cache;
static struct kmem_cache *audit_stash_cache;

/* NOTE: these sizes are based on the legacy AUDIT_BUFSIZ value designed for
 *       a 1024 byte printk buffer, some adjustment is expected */
#define AUDIT_BUF_SACNT		(AUDIT_BUFSIZ / sizeof(struct audit_stash))
#define AUDIT_BUF_SASIZE	(AUDIT_BUF_SACNT * sizeof(struct audit_stash))

static int audit_kmemcache_init(void)
{
	size_t size;

	size = sizeof(struct audit_buffer) + AUDIT_BUF_SASIZE;
	audit_buffer_cache = kmem_cache_create("audit_buffer",
					       size, 0, SLAB_PANIC, NULL);

	size = sizeof(struct audit_stash);
	audit_stash_cache = kmem_cache_create("audit_stash",
					      size, 0, SLAB_PANIC, NULL);
}

struct audit_stash *audit_stash_alloc(struct audit_buffer *ab)
{
	struct audit_stash *stash;

	if (!ab)
		return NULL;

	if (ab->s_cnt < ab->s_cnt_ab) {
		/* use the built-in stash space */
		stash = &ab->stashes[ab->s_cnt];
	} else {
		/* allocate more stash space */
		stash = kmem_cache_zalloc(audit_stash_cache, ab->gfp);
		if (!stash)
			return NULL;
		stash->flags = AUD_STSFLG_STASHFREE;
		INIT_LIST_HEAD(stash->list);
	}
	list_add_tail(&stash->list, &ab->s_list);
	ab->s_cnt++;

	return stash;
}

void __audit_stash_free(struct audit_stash *stash)
{
	if (flags & AUD_STSFLG_REF) {
		switch (stash->def->type) {
		case AUD_DTYP_CRED:
			put_cred(stash->d.cred);
			break;
		case AUD_DTYP_PATH:
			path_put(stash->d.path);
			break;
		default:
			WARN(1, "audit: unable to drop stash reference (%d)\n",
			     stash->def->code);
		}
	}

	if (flags & AUD_STSFLG_KFREE) {
		switch (stash->def->type) {
		case AUD_DTYP_TASK:
			kfree(stash->d.aud_task);
			break;
		case AUD_DTYP_STRING:
			kfree(stash->d.string);
			break;
		case AUD_DTYP_IPV4:
		case AUD_DTYP_IPV6:
			kfree(stash->d.saddr);
			break;
		case AUD_DTYP_OPAQUE:
			kfree(stash->d.buf);
			break;
		default:
			WARN(1, "audit: unable to free stash memory (%d)\n",
			     stash->def->code);
		}
	}

	kmem_cache_free(audit_stash_cache, stash);
}

void audit_stash_free(struct audit_buffer *ab, struct audit_stash *stash)
{
	if (!ab || !stash)
		return;

	list_del(stash->list);
	if (stash->flags & AUD_STSFLG_STASHFREE)
		__audit_stash_free(ab, stash);
	ab->s_cnt--;
}

struct audit_stash *audit_stash_find(struct audit_buffer *ab,
				     enum audit_data_code code,
				     struct audit_stash *start)
{
	struct audit_stash *stash;

	stash = (stash ? : list_first_entry_or_null(ab->s_list,
						    struct audit_stash,
						    s_list));
	while (stash && stash->def.code != code)
		stash = list_next_entry(stash, s_list);

	return stash;
}


struct audit_buffer *audit_buffer_alloc(int type, gfp_t gfp)
{
	struct audit_buffer *ab;

	ab = kmem_cache_zalloc(audit_buffer_cache, gfp);
	if (!ab)
		return NULL;
	ab->gfp = gfp;
	ab->type = type;
	ab->s_cnt_ab = AUDIT_BUF_SACNT;
	INIT_LIST_HEAD(ab->s_list);

	return ab;
}

void audit_buffer_free(struct audit_buffer *ab)
{
	if (!ab)
		return;

	if (ab->s_cnt > ab->s_cnt_ab) {
		struct list_head *i, *t;
		struct audit_stash *s;
		list_for_each_prev_safe(i, t, ab->s_list) {
			if (i->flags & AUD_STSFLG_STASHFREE) {
				list_del(i);
				s = list_entry(i, struct audit_stash, list));
				__audit_stash_free(s);
			} else
				/* we have released all of the stashes */
				break;
		}
	}

	kmem_cache_free(audit_buffer_cache, ab);
}
