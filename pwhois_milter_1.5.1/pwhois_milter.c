/*
 *	pwhois_milter.c v1.5.1
 *
 *	Copyright 2014 VOSTROM Holdings, Inc.
 *	This file is part of the Distribution.  See the file COPYING for details.
 */

#include <stdint.h>
#include <limits.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
#include <regex.h>
#include <libmilter/mfapi.h>

#define PWM_VERSION	"1.5.1"	// centralize

#define SIGNAL_LOG_REOPEN	SIGUSR1
#define SIGNAL_INTERRUPT	SIGUSR2

// FIXME: replace pthread_create() from signal handlers - pre-spawn threads and dedicated each one to a specific signal
// TODO: review whether raising a signal is valid to interrupt syscalls, POSIX timers, and getaddrinfo(3) - verify concept and implementation
// XXX: remove opaque and confusing wrapper macros
// DEBUG: eventually wrap pthread calls with wrappers to abort if callers skip error checks on return value
// XXX: add and check /* RC */ style comments esp. malloc and realloc
// TODO: consider pre-compiling regular expressions i.e. avoid regcomp() at runtime just before each regexec()
// LOG: if dropping privileges, fork(2) first and socketpair(2) for Unix domain socket - on signal caught by parent to re-open(2) log file, pass fd via SCM_RIGHTS cmsg(3)
// TODO: look for items which should really get checked at compile time

#ifndef MAP_FAILED
#define MAP_FAILED	((void *)-1)
#endif

// warn on incompatible format strings and arguments for [sn|d]printf wrappers
#if defined(__GNUC__) || defined(__clang__)
#	define FN_VA_FMT_PRINTF_ATTR(x, y)	__attribute__ ((__format__ (__printf__, (x), (y))))
#else
#	define FN_VA_FMT_PRINTF_ATTR(x, y)
#endif

#ifndef ARRAY_LEN
#	define ARRAY_LEN(x)		(sizeof (x) / sizeof *(x))
#endif
#ifndef PTR_FREE
#	define PTR_FREE(ptr)		do { if (ptr != NULL) { free(ptr); (ptr) = NULL; } } while (0)
#endif
#ifndef PTR_TAKE
#	define PTR_TAKE(pdst, psrc)	do { (pdst) = (psrc); (psrc) = NULL; } while (0)
#endif
#ifndef MIN
#	define MIN(a, b)		(((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#	define MAX(a, b)		(((a) > (b)) ? (a) : (b))
#endif


union ipv4 {
	uint32_t	addr;
	uint8_t		octet[4];
};

struct thread_timer;

struct filter_state {
	bool		is_msg_ok;
	union ipv4	peer;
	bool		is_valid_peer;
	bool		got_mta_info;	// already added by preceding Milter - keep: earlier info likely more relevant wrt. organizational boundaries
	bool		was_processed;
	union ipv4	ip;
	bool		is_valid_ip;
	char		*user_agent;
	char		*from_domain;
	struct thread_timer *timer;
};

struct thread_timer {
	bool		timed_out;
	timer_t		timer_id;
	pthread_t	thread;
	pthread_mutex_t	is_valid_thread_lock;
	bool		is_valid_thread;
	struct filter_state *state;	// parent
	struct thread_timer *prev;
	struct thread_timer *next;
};

struct getaddrinfo_params {
	struct filter_state *state;
	const char	*host;
	const char	*service;
	struct addrinfo	*hints;
	struct addrinfo	**result;
	pthread_cond_t	cond;
	int		retval;
	int		errnum;
};


struct ipnet {
	union ipv4	net;
	uint_fast8_t	cidr;
};

struct ipnet	*g_ignore_nets = NULL;
unsigned	g_ignore_count = 0;

// XXX TODO: combine into single global struct
unsigned	g_debug_level = 0;
unsigned	g_default_timeout_sec = 5;
unsigned	g_timeout_sec = 5;	// initialize to default above
char		*g_default_pwhois_host = "whois.pwhois.org";
char		*g_pwhois_host;
bool		g_is_default_pwhois_host = true;
char		*g_default_pwhois_port = "43";
char		*g_pwhois_port;
bool		g_is_default_pwhois_port = true;
char		*g_default_milter_socket_spec = "inet:8472@localhost";
char		*g_milter_socket_spec;
bool		g_is_default_milter_socket_spec = true;
char		*g_default_header_prefix = "X-PWhois-";
char		*g_header_prefix;
bool		g_is_default_header_prefix = true;
char		*g_default_mta_header = "Deliverer-";
char		*g_mta_header;
bool		g_is_default_mta_header = true;

clockid_t	g_clock_id = CLOCK_REALTIME;
pthread_mutex_t	g_thread_timer_lock = PTHREAD_MUTEX_INITIALIZER;
struct thread_timer *g_thread_timer_list = NULL;

pthread_mutex_t	g_logger_lock = PTHREAD_MUTEX_INITIALIZER;
char		*g_logfilename = NULL;
FILE		*g_logfile = NULL;
pthread_mutex_t	g_strerror_lock = PTHREAD_MUTEX_INITIALIZER;


static void FN_VA_FMT_PRINTF_ATTR(1, 2) log_printf(const char *templ, ...)
{
	va_list		ap;
	char		buf[64];		// holds only TS string
	int		rv, bufsz = sizeof buf, locked = 0;
	time_t		tm;
	struct tm	tms;

	pthread_mutex_lock(&g_logger_lock); locked = 1;
	if (g_logfile == NULL) goto fail;

	if ((tm = time(NULL)) < 0 || gmtime_r(&tm, &tms) == NULL
	|| (rv = (strftime(buf, bufsz, "%b %Od %Y %H:%M:%S", &tms)) <= 0)
	|| rv >= bufsz) goto fail;
	fprintf(g_logfile, "%s: ", buf);	// prefix: timestamp similar to syslog style

	va_start(ap, templ);
	vfprintf(g_logfile, templ, ap);		// expects caller to include trailing line feed
	va_end(ap);

	fflush(g_logfile);
fail:
	if (locked) pthread_mutex_unlock(&g_logger_lock);
}


static int FN_VA_FMT_PRINTF_ATTR(4, 0) pw_vsnprintf(char *buf, int size, int pos, const char *fmt, va_list ap)
{
	int	ret = -1, len, avail;

	if (size <= 0 || pos < 0 || pos >= size - 1) goto fail;
	avail = size - pos;

	len = vsnprintf(buf + pos, avail, fmt, ap);		// append
	if (len < 0 || len >= avail) goto fail;

	ret = pos + len;
fail:
	return ret;
}

static int FN_VA_FMT_PRINTF_ATTR(4, 5) pw_snprintf(char *buf, int size, int pos, const char *fmt, ...)
{
	va_list	ap;
	int	ret;

	va_start(ap, fmt);
	ret = pw_vsnprintf(buf, size, pos, fmt, ap);
	va_end(ap);

	return ret;
}

static int pw_strerror_r(int errnum, char *buf, size_t size)
{
	int	ret = ENOSPC, rv = -1, errval = errno;
	char	*str = NULL;

	if (buf == NULL || size <= 0) goto fail;
	*buf = '\0';
	errno = 0;

#if defined(_GNU_SOURCE)

	str = strerror_r(errnum, buf, size);			// GNU-specfic

#elif (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L) || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 600)

	rv = strerror_r(errnum, buf, size);			// XSI-compliant

	if (rv == 0 && *buf != '\0') str = buf;

#else

	str = strerror(errnum);					// copy to buf below - XXX: MT-Unsafe due to possible race condition

#endif

	if (str == NULL) {
		(void)pw_snprintf(buf, size, 0, "Unknown errno %d error %d", errnum, (rv < 0 ? errno : rv));

	} else if (*str != '\0' && *buf == '\0') {		// copy into buf - glibc can return static string and leave buf empty
		strncpy(buf, str, size);
		buf[size - 1] = '\0';
	}

fail:
	errno = errval;
	return ret;
}


static char *pw_strerror_p(int errnum, char *buf, size_t size)
{
	char	*str = (char *)"?!";

	if (buf == NULL || size <= 0) goto fail;

	(void)pw_strerror_r(errnum, buf, size);

	str = buf;
fail:
	return str;
}


static void log_perror(char *str, int errnum)
{
	char	buf[64];
	pthread_mutex_lock(&g_strerror_lock);	// overly protective - only needed for legacy race condition
	log_printf("%s: %s\n", str, pw_strerror_p(errnum, buf, sizeof buf));
	pthread_mutex_unlock(&g_strerror_lock);
}

#define LOG_OUT_OF_MEMORY	do { log_printf("Error: Out of memory\n"); } while (0)


static void *log_reopen(void *logger_lock)
{
	pthread_mutex_lock((pthread_mutex_t *)&logger_lock);
	if (g_logfile != NULL) fclose(g_logfile);
	g_logfile = fopen(g_logfilename, "a");
	pthread_mutex_unlock((pthread_mutex_t *)&logger_lock);
	return NULL;
}


static void signal_log_reopen(int signum)
{
	pthread_t	thread;
	if (signum != SIGNAL_LOG_REOPEN) return;
	if (pthread_create(&thread, NULL, &log_reopen, &g_logger_lock) == 0) pthread_detach(thread);	// auto reap
}


static void sigstub(int signum)
{
	if (signum == SIGNAL_INTERRUPT) return;
}


static void timer_expired(union sigval timer)
{
	struct thread_timer	*node = timer.sival_ptr;

	pthread_mutex_lock(&g_thread_timer_lock);
	node->timed_out = true;
	pthread_mutex_lock(&node->is_valid_thread_lock);
	if (node->is_valid_thread) pthread_kill(node->thread, SIGNAL_INTERRUPT);	// fire
	pthread_mutex_unlock(&node->is_valid_thread_lock);
	pthread_mutex_unlock(&g_thread_timer_lock);
}


static void filter_state_cleanup(struct filter_state *state, bool valid_timer_id)
{
	PTR_FREE(state->user_agent);
	PTR_FREE(state->from_domain);
	if (state->timer == NULL) return;
	pthread_mutex_lock(&g_thread_timer_lock);
	if (valid_timer_id && timer_delete(state->timer->timer_id) != 0) log_perror("Error: timer_delete()", errno);
	if (state->timer->prev == NULL) {
		g_thread_timer_list = state->timer->next;
	} else {
		state->timer->prev->next = state->timer->next;
	}
	if (state->timer->next != NULL) state->timer->next->prev = state->timer->prev;
	pthread_mutex_destroy(&state->timer->is_valid_thread_lock);	// XXX: race or timer_delete()? - could timer_expired() fire after free() incl. queue/delay then contend on global lock?
	PTR_FREE(state->timer);
	pthread_mutex_unlock(&g_thread_timer_lock);
}


static struct filter_state *filter_state_reset(SMFICTX *ctx, bool is_new_conn)
{
	struct filter_state	*pret = NULL, *state = smfi_getpriv(ctx);
	struct sigevent		sev;
	struct itimerspec	ts;
	bool			valid_timer_id = false, did_alloc = false;

	if (state == NULL) {
		state = malloc(sizeof(*state));
		if (state == NULL) { LOG_OUT_OF_MEMORY; goto fail; }
		state->is_valid_peer = false;
		did_alloc = true;
	} else {
		filter_state_cleanup(state, true);	// reuse - destroy resources before re-init below
		if (is_new_conn) state->is_valid_peer = false;
	}
	if (did_alloc && smfi_setpriv(ctx, state) != MI_SUCCESS) goto fail;

	state->is_msg_ok = true;
	state->got_mta_info = false;
	state->was_processed = false;
	state->is_valid_ip = false;
	state->user_agent = NULL;
	state->from_domain = NULL;
	state->timer = NULL;
	if (is_new_conn) goto success;

	state->timer = malloc(sizeof *state->timer);
	if (state->timer == NULL) { LOG_OUT_OF_MEMORY; goto fail; }

	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_value.sival_ptr = state->timer;
	sev.sigev_notify_function = &timer_expired;
	sev.sigev_notify_attributes = NULL;
	if (timer_create(g_clock_id, &sev, &state->timer->timer_id) != 0) { log_perror("Error: timer_create()", errno); goto fail; }	// XXX: fatal will free - thus lose peer IP for subsequent messages
	valid_timer_id = true;

	state->timer->timed_out = false;
	ts.it_value.tv_sec = g_timeout_sec;
	ts.it_value.tv_nsec = ts.it_interval.tv_sec = ts.it_interval.tv_nsec = 0;
	if (timer_settime(state->timer->timer_id, 0, &ts, NULL) != 0) { log_perror("Error: timer_settime()", errno); goto fail; }

	state->timer->thread = pthread_self();
	pthread_mutex_init(&state->timer->is_valid_thread_lock, NULL);
	state->timer->is_valid_thread = true;
	state->timer->state = state;

	pthread_mutex_lock(&g_thread_timer_lock);
	state->timer->prev = NULL;
	if (g_thread_timer_list != NULL) g_thread_timer_list->prev = state->timer;
	state->timer->next = g_thread_timer_list;
	g_thread_timer_list = state->timer;
	pthread_mutex_unlock(&g_thread_timer_lock);
success:
	PTR_TAKE(pret, state);
fail:
	if (state != NULL) { filter_state_cleanup(state, valid_timer_id); PTR_FREE(state); }
	return pret;
}

static struct filter_state *filter_state_init(SMFICTX *ctx)	// per message
{
	return filter_state_reset(ctx, false);
}

static struct filter_state *filter_state_new(SMFICTX *ctx)	// connection
{
	return filter_state_reset(ctx, true);
}


static sfsistat filter_state_end(struct filter_state *state)	// per message
{
	if (state == NULL) return SMFIS_ACCEPT;
	if (state->timer != NULL) {
		pthread_mutex_lock(&state->timer->is_valid_thread_lock);
		state->timer->is_valid_thread = false;
		pthread_mutex_unlock(&state->timer->is_valid_thread_lock);
	}
	return SMFIS_CONTINUE;
}


static sfsistat cleanup_event(SMFICTX *ctx, bool is_close_conn)
{
	sfsistat		ret = SMFIS_ACCEPT;
	struct filter_state	*state = smfi_getpriv(ctx);

	if (state == NULL) goto fail;
	if (is_close_conn) {
		filter_state_cleanup(state, true);
		PTR_FREE(state);	// sets NULL
		if (smfi_setpriv(ctx, state) != MI_SUCCESS) goto fail;
	} else {
		state->is_msg_ok = false;
		filter_state_end(state);
	}
	ret = SMFIS_CONTINUE;
fail:
	return ret;
}


static sfsistat cleanup(SMFICTX *ctx)				// per message
{
	return cleanup_event(ctx, false);
}

static sfsistat cleanup_done(SMFICTX *ctx)			// connection
{
	return cleanup_event(ctx, true);
}


static sfsistat cleanup_fail(SMFICTX *ctx)			// per message
{
	cleanup(ctx);
	return SMFIS_ACCEPT;
}

static sfsistat cleanup_error(SMFICTX *ctx)			// connection
{
	cleanup_done(ctx);
	return SMFIS_ACCEPT;
}


static struct filter_state *filter_state_begin(SMFICTX *ctx)	// per message
{
	struct filter_state	*pret = NULL, *state = smfi_getpriv(ctx);

	if (state == NULL) { log_printf("Error: smfi_getpriv(ctx) returned NULL\n"); goto fail; }
	if (state->timer->timed_out) { log_printf("Notice: timed out - cleaning up\n"); state->is_msg_ok = false; goto fail; }
	if (!state->is_msg_ok) goto fail;		// earlier callback
	pthread_mutex_lock(&state->timer->is_valid_thread_lock);
	state->timer->thread = pthread_self();
	state->timer->is_valid_thread = true;
	pthread_mutex_unlock(&state->timer->is_valid_thread_lock);
	PTR_TAKE(pret, state);
fail:
	if (state != NULL) cleanup_fail(ctx);		// invalidate
	return pret;
}


static int sendn(struct filter_state *state, int fd, const char *buf, size_t len)
{
	int	ret = -1;
	ssize_t	rv;
	size_t	sent = 0;

	while (sent < len) {	// if len == 0 then skip and return 0
		rv = send(fd, buf + sent, len - sent, 0);
		if (rv == 0) continue;	// XXX: give up now or allow just once?
		if (rv < 0) {
			if (errno != EINTR) { log_perror("Error: send()", errno); goto fail; }
			if (state->timer->timed_out) { log_printf("Timeout: send() aborted\n"); goto fail; }
			continue;
		}
		sent += rv;
	}

	ret = sent;
fail:
	return ret;
}


static bool sendstr(struct filter_state *state, int fd, const char *str)
{
	ssize_t	len = strlen(str);
	return sendn(state, fd, str, len) == len;
}


static int recvn(struct filter_state *state, int fd, char *buf, size_t len)
{
	int	ret = -1;
	ssize_t	rv;
	size_t	received = 0;

	while (received < len) {	// if len == 0 then skip and return 0
		rv = recv(fd, buf + received, len - received, 0);
		if (rv == 0) break;
		if (rv < 0) {
			if (errno != EINTR) { log_perror("Error: recv()", errno); goto fail; }
			if (state->timer->timed_out) { log_printf("Timeout: recv() aborted\n"); goto fail; }
			continue;
		}
		received += rv;
	}

	ret = received;
fail:
	return ret;
}


static char *recvstr(struct filter_state *state, int fd, size_t *sz)
{
	char	*pret = NULL, *response = NULL, *tmp;
	size_t	pos, len = 0;
	ssize_t	retval;

	do {
		pos = len;
		len += 4096;
		tmp = realloc(response, len);
		if (tmp == NULL) { LOG_OUT_OF_MEMORY; goto fail; }
		response = tmp;
		retval = recvn(state, fd, response + pos, len - pos);
		if (retval < 0) goto fail;
	} while (retval == (ssize_t)(len - pos));
	pos += retval;
	tmp = realloc(response, pos + 1);	// XXX: might be counter-productive for caller
	if (tmp != NULL) response = tmp;	// ignore if unable to shrink - not fatal

	response[pos] = '\0';
	PTR_TAKE(pret, response);
fail:
	PTR_FREE(response);
	if (pret == NULL) pos = 0;
	if (sz != NULL) *sz = pos;
	return pret;
}


static void *getaddrinfo_thread(void *arg)
{
	struct getaddrinfo_params	*gaip = arg;

	do {
		gaip->retval = getaddrinfo(gaip->host, gaip->service,
		gaip->hints, gaip->result);
	} while (gaip->retval == EAI_SYSTEM && errno == EINTR && !gaip->state->timer->timed_out);
	gaip->errnum = errno;
	/* RC */pthread_cond_signal(&gaip->cond);	// XXX TODO FIXME: must lock mutex otherwise PThreads implementation is permitted not to wake up waiter
	return gaip;
}


static int connect_host(struct filter_state *state, const char *host, const char *service)
{
	struct addrinfo		hints, *result = NULL, *rp;
	struct getaddrinfo_params	gaip = {
		.state = state,
		.host = host,
		.service = service,
		.hints = &hints,
		.result = &result
	};
	pthread_mutex_t		lock = PTHREAD_MUTEX_INITIALIZER;
	pthread_t		thread;
	struct itimerspec	its;
	struct timespec		ts;
	int			retval, fd = -1;
	pthread_condattr_t	attr;

	retval = pthread_condattr_init(&attr);
	if (retval != 0) { log_perror("Error: pthread_condaddr_init()", retval); return -1; }

	// see posixoptions(7) manpage

#define PTHREAD_SET_CLOCK_ID \
	retval = pthread_condattr_setclock(&attr, g_clock_id); \
	if (retval != 0) { log_perror("Error: pthread_condattr_setclock()", retval); return -1; }

#ifdef _POSIX_CLOCK_SELECTION
#	if _POSIX_CLOCK_SELECTION != -1
		PTHREAD_SET_CLOCK_ID
#	endif
#else
	PTHREAD_SET_CLOCK_ID
#endif

	retval = pthread_cond_init(&gaip.cond, &attr);
	if (retval != 0) { log_perror("Error: pthread_cond_init()", retval); return -1; }

	pthread_mutex_lock(&lock);
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	retval = pthread_create(&thread, NULL, &getaddrinfo_thread, &gaip);
	if (retval != 0) { log_perror("Error: pthread_create()", retval); return -1; }
	if (timer_gettime(state->timer->timer_id, &its) != 0) { log_perror("Error: timer_gettime()", errno); return -1; }
	clock_gettime(g_clock_id, &ts);
	ts.tv_sec += its.it_value.tv_sec;
	ts.tv_nsec += its.it_value.tv_nsec;
	if (ts.tv_nsec > 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
	retval = pthread_cond_timedwait(&gaip.cond, &lock, &ts);	// XXX TODO FIXME: loop to protect against spurious wakeup
	pthread_cancel(thread);
	pthread_join(thread, NULL);
	pthread_mutex_unlock(&lock);
	pthread_condattr_destroy(&attr);
	pthread_cond_destroy(&gaip.cond);
	if (retval == ETIMEDOUT) {
		log_printf("Timeout: getaddrinfo() aborted\n");
		/* Resolve a race to access free()'d memory in timer_expired() */
		while (!state->timer->timed_out) continue;	/* pause() would introduce a small race */
		return -1;
	}
	retval = gaip.retval;
	errno = gaip.errnum;
	if (retval != 0) {
		if (retval == EAI_SYSTEM && errno == EINTR && state->timer->timed_out) { log_printf("Timeout: getaddrinfo() aborted\n"); return -1; }
		log_printf("Error: getaddrinfo(): %s\n", gai_strerror(retval));
		return -1;
	}
	if (result == NULL) { log_printf("Error: getaddrinfo() returned a NULL result\n"); return -1; }
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		do {
			fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (fd < 0) {
				if (errno != EINTR) break;
				if (state->timer->timed_out) { log_printf("Timeout: socket() aborted\n"); freeaddrinfo(result); return -1; }
			}
		} while (fd < 0 && errno == EINTR);

		if (fd < 0) continue;
		do {
			retval = connect(fd, rp->ai_addr, rp->ai_addrlen);
			if (retval != 0) {
				if (errno != EINTR) break;
				if (state->timer->timed_out) { log_printf("Timeout: connect() aborted\n"); freeaddrinfo(result); close(fd); return -1; }
			}
		} while (retval != 0 && errno == EINTR);

		if (retval == 0) break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(result);
	if (fd < 0 || retval != 0) { log_perror("Error: socket() or connect()", errno); return -1; }
	return fd;
}


static bool is_routeable_ip(const union ipv4 *ip)
{
	return ip->octet[0] != 0 && ip->octet[0] != 10 && ip->octet[0] != 127
	&& (ip->octet[0] != 169 || ip->octet[1] != 254)
	&& (ip->octet[0] != 172 || ip->octet[1] < 16 || ip->octet[1] > 31)
	&& (ip->octet[0] != 192 || ip->octet[1] != 168);
}


static bool is_ignored_net(const union ipv4 *ip)
{
	bool		ret = false;
	unsigned	k, mask, hbo = ntohl(ip->addr);
	struct ipnet	*pnet;
	for (k = 0, pnet = g_ignore_nets; pnet != NULL && k < g_ignore_count; k++, pnet++) {
		mask = ~(pnet->cidr == 0 ? ~0 : (1 << (32 - pnet->cidr)) - 1);
		if ((hbo & mask) == (ntohl(pnet->net.addr) & mask)) { ret = true; break; }
	}
	return ret;
}


static sfsistat mail_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
	bool			tret = false;
	struct filter_state	*state = filter_state_new(ctx);
	int			af, errnum;
	unsigned		port = 0;
	const void		*psa = NULL;
	char			buf[INET6_ADDRSTRLEN] = "<NULL>", tmp[5 + 1] = "<N/A>";
	struct	sockaddr_in	sin = { 0 };
	struct	sockaddr_in6	sin6 = { 0 };

	if (hostaddr != NULL) {
		af = hostaddr->sa_family;
		switch (af) {
		case AF_INET:
			if (psa == NULL) {
				memcpy(&sin, hostaddr, sizeof sin);
				port = sin.sin_port;
				psa = &sin.sin_addr;
				if (state != NULL) { state->peer.addr = sin.sin_addr.s_addr; state->is_valid_peer = true; }
			}
			// fall through
		case AF_INET6:
			if (psa == NULL) { memcpy(&sin6, hostaddr, sizeof sin6); port = sin6.sin6_port; psa = &sin6.sin6_addr; }
			if (inet_ntop(af, psa, buf, sizeof buf) != NULL) { snprintf(tmp, sizeof tmp, "%u", port); break; }
			errnum = errno;
			snprintf(buf, sizeof buf, "[%s]", strerror(errnum));
			snprintf(tmp, sizeof tmp, "%d", errnum);
			break;
		default:
			snprintf(buf, sizeof buf, af == AF_UNSPEC ? "[AF_UNSPEC]" : (af == AF_UNIX ? "[AF_UNIX]" : "[AF_???]"));
			snprintf(tmp, sizeof tmp, "%d", af);
			break;
		}
	}

#ifdef NDEBUG
	(void)hostname;
	(void)buf;
	(void)tmp;
#else
	log_printf("Debug:\t\t" "CONNECT -\t" "ctx = %p, hostname = %s, hostaddr = %s:%s\n"
	, ctx, (hostname == NULL ? "<NULL>" : hostname), buf, tmp);
#endif

	if (state == NULL || (state->is_valid_peer && is_routeable_ip(&state->peer) && is_ignored_net(&state->peer))) goto fail;
	tret = true;
fail:
	return tret ? filter_state_end(state) : cleanup_error(ctx);
}


static sfsistat mail_envfrom(SMFICTX *ctx, char *argv[])
{
	struct filter_state	*state = filter_state_init(ctx);
	char	*domain, *domain_end;
	size_t	domain_len;

	if (state == NULL) return cleanup_fail(ctx);

	domain = strchr(argv[0], '@');
	if (domain == NULL) return filter_state_end(state);
	domain_end = strchr(++domain, '>');

	domain_len = (domain_end == NULL ? strlen(domain) : (size_t)(domain_end - domain));

	if (domain_len == 0) return filter_state_end(state);
	state->from_domain = malloc(domain_len + 1);
	if (state->from_domain == NULL) { LOG_OUT_OF_MEMORY; return cleanup_fail(ctx); }

	memcpy(state->from_domain, domain, domain_len);
	state->from_domain[domain_len] = '\0';
	return filter_state_end(state);
}


static void regerror_print(int retval, regex_t *reg)
{
	size_t	msgsize = regerror(retval, reg, NULL, 0);
	char	*msg = malloc(msgsize);

	if (msg == NULL) { LOG_OUT_OF_MEMORY; return; }
	regerror(retval, reg, msg, msgsize);
	log_printf("Error: regcomp() %s\n", msg);
	free(msg);
}


static bool regex_match(char *pat, char *str, size_t n, regmatch_t *match)
{
	regex_t	reg;
	int	retval = regcomp(&reg, pat, REG_EXTENDED | REG_ICASE) != 0;	// FIXME: int vs. int => bool - XXX TODO: pre-compile patterns

	if (retval != 0) { regerror_print(retval, &reg); return false; }	// FIXME: bool vs. int
	retval = regexec(&reg, str, n, match, 0);
	regfree(&reg);
	if (retval != 0) { match[0].rm_so = -1; match[0].rm_eo = -1; }
	return true;
}


static bool ipv4_sscan_brackets(const char *str, union ipv4 *ip)
{
	return sscanf(str, "[%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"]", &ip->octet[0], &ip->octet[1], &ip->octet[2], &ip->octet[3]) == 4;
}

static bool ipv4_sscan(const char *str, union ipv4 *ip)
{
	return sscanf(str, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &ip->octet[0], &ip->octet[1], &ip->octet[2], &ip->octet[3]) == 4;
}


static bool parse_received(char *value, struct filter_state *state)
{
	char		*rcvd_from, *rcvd_ip, *rcvd_ip_end, *rcvd_end, ch, chf;
	regmatch_t	match[3];
	union ipv4	ip;
	bool		retval, is_valid_ip = false;

	if (!regex_match("^[[:space:]]*from[[:space:]]+(.*)", value, 2, match)) return false;
	if (match[0].rm_so < 0 || match[1].rm_so < 0) return true;
	rcvd_from = value + match[1].rm_so;
	rcvd_end = value + match[1].rm_eo;
	chf = *rcvd_end;	// FIXME: do not modify in place - XXX TODO: unless allocated and not owned by API
	*rcvd_end = '\0';
	if (!regex_match("^.*[[:space:]]+by", rcvd_from, 1, match)) goto restore_fatal;
	if (!regex_match("^.*[[:space:]]+for", rcvd_from, 1, match + 1)) goto restore_fatal;
	if (!regex_match("^.*[[:space:]]+with", rcvd_from, 1, match + 2)) goto restore_fatal;
	if ((match[0].rm_so >= 0 && match[0].rm_eo >= 0)
	|| (match[1].rm_so >= 0 && match[1].rm_eo >= 0)
	|| (match[2].rm_so >= 0 && match[2].rm_eo >= 0)) {
		if (match[0].rm_eo < 0
		|| (match[0].rm_eo > match[1].rm_eo && match[1].rm_eo >= 0))
			match[0].rm_eo = match[1].rm_eo;
		if (match[0].rm_eo < 0
		|| (match[0].rm_eo > match[2].rm_eo && match[2].rm_eo >= 0))
			match[0].rm_eo = match[2].rm_eo;
		*rcvd_end = chf;
		rcvd_end = rcvd_from + match[0].rm_eo;
		chf = *rcvd_end;
		*rcvd_end = '\0';
	}
	rcvd_ip = rcvd_from;
	do {
		if (!regex_match(
		"[^-.@A-Za-z0-9]*(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
		"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))[^-.@A-Za-z0-9]+",
		rcvd_ip, 2, match))
			goto restore_fatal;
		if (match[0].rm_so < 0 || match[1].rm_so < 0) goto restore_ok;
		rcvd_ip_end = rcvd_ip + match[1].rm_eo;
		rcvd_ip += match[1].rm_so;
		ch = *rcvd_ip_end;
		*rcvd_ip_end = '\0';
		if (ipv4_sscan(rcvd_ip, &ip) && is_routeable_ip(&ip)) is_valid_ip = true;
		*rcvd_ip_end = ch;
		rcvd_ip = rcvd_ip_end;
	} while (!is_valid_ip);

	if (is_valid_ip) { state->ip.addr = ip.addr; state->is_valid_ip = true; }
restore_ok:
	retval = true;
restore:
	*rcvd_end = chf;
	return retval;
restore_fatal:
	retval = false;
	goto restore;
}


static sfsistat mail_header(SMFICTX *ctx, char *header, char *value)
{
	bool			tret = false, filtered_prior = false;
	struct filter_state	*state = filter_state_begin(ctx);
	union ipv4		ip;

	if (state == NULL) goto fail;

	if (g_mta_header[0] != '\0'	// unless disabled via empty qualifier: check whether header begins with concatenated prefix and qualifier
	&& (g_header_prefix[0] == '\0' || strncasecmp(header, g_header_prefix, strlen(g_header_prefix)) == 0)
	&& strncasecmp(header + strlen(g_header_prefix), g_mta_header, strlen(g_mta_header)) == 0) {	// XXX: for completeness, no user demand - currently no mode implemented to relay MTA peer info instead of or in preference to Received i.e. extra option in addition to empty qualifier which just disables right now
		state->got_mta_info = true;
		filtered_prior = true;
	}
	if (g_header_prefix[0] == '\0'	// if empty string then look exactly for known suffix - otherwise check for prefix (XXX: independent of qualifier match above, always have at least one header present here even if ran older version on earlier instance/server - so BTW in strange case of multiple chained, and first did not support/have qualifier or fetch distinct routeable IP then later peer may be added to earlier Received)
	? (strcasecmp(header, "Origin") == 0 || strcasecmp(header, "Status") == 0)
	: strncasecmp(header, g_header_prefix, strlen(g_header_prefix)) == 0) {
		state->was_processed = true;
		filtered_prior = true;
	}
	if (filtered_prior) goto success;

	if (strcasecmp(header, "X-Mailer") == 0
	|| strcasecmp(header, "User-Agent") == 0) {
		if (state->user_agent != NULL) goto success;
		for ( ; *value != '\0' && isspace((unsigned char)*value); value++) continue;
		state->user_agent = strdup(value);
		if (state->user_agent == NULL) { LOG_OUT_OF_MEMORY; goto fail; }
		goto success;
	}

	if (strcasecmp(header, "Received") == 0) {
		if (!parse_received(value, state)) goto fail;
		goto success;
	}

	if (strcasecmp(header, "X-Originating-IP") == 0
	&& (ipv4_sscan_brackets(value, &ip) || ipv4_sscan(value, &ip))
	&& is_routeable_ip(&ip)) {
		state->ip.addr = ip.addr;
		state->is_valid_ip = true;
	}
success:
	tret = true;
fail:
	return tret ? filter_state_end(state) : cleanup_fail(ctx);
}


static char *coerce2ascii(const char *str)
{
	char		*pret = MAP_FAILED, *ptr, *buf = NULL;
	const char	*pch;
	unsigned char	uch;
	int		bufsz = 0, pos;

	if (str == NULL) goto success;

	for (pch = str; (uch = *pch) != '\0'; pch++) {
		if (uch >= 0x20 && uch < 0x7f) continue;	// allow ASCII (non-CTRL)
		pos = pch - str;
		if (buf == NULL) {
			bufsz = pos + 1 + strlen(pch + 1) + 1;
			buf = malloc(bufsz);
			if (buf == NULL) goto fail;
			memcpy(buf, str, bufsz);		// incl. terminator
		}
		ptr = buf + pos;		// mutable
		*ptr = (uch == 0x09 || uch == 0x0a || uch == 0x0d) ? ' ' : '.';	// substitute WSP or non-ASCII
		str = buf;
		pch = str + pos;		// rebase
	}

success:
	PTR_TAKE(pret, buf);
fail:
	if (buf != MAP_FAILED) PTR_FREE(buf);
	return pret;
}


static bool add_header(SMFICTX *ctx, const char *str, const char *fieldname, const char *field)
{
	bool	ret = false;
	char	header[64], *buf = NULL;
	int	rv, hdrsz = sizeof header;

	if ((rv = snprintf(header, hdrsz, "%s%s%s", g_header_prefix, str == NULL ? "" : str, fieldname)) < 0 || rv >= hdrsz) { log_printf("Error: Oversized field name: %s%s%s\n", g_header_prefix, str, fieldname); goto fail; }
	buf = coerce2ascii(field);
	if (buf == MAP_FAILED) { log_printf("Fatal error in coerce2ascii()\n"); goto fail; }
	if (buf != NULL) field = buf;
	if (smfi_addheader(ctx, header, (char *)field) != MI_SUCCESS) { log_printf("Error adding field %s\n", fieldname); goto fail; }

	ret = true;
fail:
	if (buf != MAP_FAILED) PTR_FREE(buf);
	return ret;
}


static bool add_header_field(SMFICTX *ctx, char *response, size_t rlen, const char *str, const char *fieldname)
{
	char ch, *field, *field_end = NULL;
	size_t fieldnamelen = strlen(fieldname);
	bool retval = false;

	if (fieldnamelen > rlen) return true;
	field = response;	// mutable - allocated by caller
	while (true) {
		field = strstr(field, fieldname);
		if (field == NULL) return true;
		if ((field == response || field[-1] == '\n')
		&& ((response + rlen - field - fieldnamelen) >= 1)
		&& field[fieldnamelen] == ':')
			break;
		field++;
	}
	field += fieldnamelen + 1;
	while (*field != '\0' && *field != '\n' && isspace((unsigned char)*field)) field++;	/* WSP */

	if (field[0] == '\0' || field[0] == '\n'
	|| (field[0] == '-' && (field[1] == '\0' || field[1] == '\n'))
	|| (field[0] == 'N' && field[1] == 'U' && field[2] == 'L'
	&& field[3] == 'L' && (field[4] == '\0' || field[4] == '\n')))
		return true;
	for (field_end = field; *field_end != '\0' && *field_end != '\n'; field_end++) continue;
	ch = *field_end;
	*field_end = '\0';
	if (!add_header(ctx, str, fieldname, field)) goto fail;

	retval = true;
fail:
	if (field_end != NULL) *field_end = ch;	// restore
	return retval;
}


static bool add_header_ip(SMFICTX *ctx, const union ipv4 *v4ip, const char *str)
{
	bool	ret = false;
	char	host[16];
	int	rv, hostsz = sizeof host;

	if ((rv = snprintf(host, hostsz, "%u.%u.%u.%u"
	, v4ip->octet[0], v4ip->octet[1], v4ip->octet[2], v4ip->octet[3])) < 0 || rv >= hostsz)
		goto fail;
	ret = add_header(ctx, str, "Origin", host);
fail:
	return ret;
}


static int supplement_headers(SMFICTX *ctx, struct filter_state *state, bool valid_ip, const union ipv4 *v4ip, bool is_peer, const char *str)
{
	char	request[1024], *response = NULL;
	int	ret = -1, rv, k, fd = -1, reqsz = sizeof request;
	size_t	responselen;

	if (!valid_ip) {
		if (!is_peer && !state->was_processed && !add_header(ctx, NULL, "Status", "No originator identified")) goto fail;
		goto success;
	}

	fd = connect_host(state, g_pwhois_host, g_pwhois_port);
	if (fd < 0) goto fail;	// XXX: timeout is fatal whether connect or I/O etc. - none of our headers get appended (except Status when not routeable above or also if empty/tempfail response below - yet query for peer info times out after Received which just omits that)

	for (k = 0; k <= 2; k++) {	// reduce if oversized - drop UA etc. if needed (XXX: very unlikely case)
		rv = snprintf(request, reqsz, "app=\"PWhois-Milter-v" PWM_VERSION " %s %s\"\n" "%u.%u.%u.%u\n"
		, (k <= 1 ? (state->from_domain == NULL ? "-unknown-" : state->from_domain) : "-")
		, (k <= 0 ? (state->user_agent == NULL ? "-unknown-" : state->user_agent) : "-")
		, v4ip->octet[0], v4ip->octet[1], v4ip->octet[2], v4ip->octet[3]);
		if (rv >= 0 && rv < reqsz) break;
		if (k >= 2) { log_printf("Error: Request to PWhois is too large\n"); goto fail; }	// XXX: error with truncated variant? - not possible
	}
	if (!sendstr(state, fd, request)) goto fail;
	response = recvstr(state, fd, &responselen);
	if (response == NULL) goto fail;

	if (strncasecmp(response, "Error", 5) == 0 || strncasecmp(response, "Sorry", 5) == 0) { log_printf("Warning: pwhois replied: %s", response); goto success; }	// soft error - let caller proceed e.g. during temporary outage
	if (!is_peer && state->was_processed) { log_printf("Info: Message was already processed by a previous PWhois Milter\n"); goto success; }

	if (!add_header_ip(ctx, v4ip, str)
	|| !add_header_field(ctx, response, responselen, str, "Origin-AS")
	|| !add_header_field(ctx, response, responselen, str, "AS-Path")
	|| !add_header_field(ctx, response, responselen, str, "Route-Originated-Date")
	|| !add_header_field(ctx, response, responselen, str, "Route-Originated-TS")
	|| !add_header_field(ctx, response, responselen, str, "AS-Org-Name")
	|| !add_header_field(ctx, response, responselen, str, "Org-Name")
	|| !add_header_field(ctx, response, responselen, str, "Net-Name")
	|| !add_header_field(ctx, response, responselen, str, "City")
	|| !add_header_field(ctx, response, responselen, str, "Region")
	|| !add_header_field(ctx, response, responselen, str, "Country")
	|| !add_header_field(ctx, response, responselen, str, "Country-Code"))
		goto fail;
	ret = 1;
success:
	if (ret < 0) ret = 0;
fail:
	PTR_FREE(response);
	if (fd >= 0 && close(fd) != 0) log_perror("close(pwhois)", errno);
	return ret;
}


static sfsistat mail_eom(SMFICTX *ctx)
{
	bool			tret = false, trv = true;
	struct filter_state	*state = filter_state_begin(ctx);

	if (state == NULL || (state->is_valid_ip && is_ignored_net(&state->ip))) goto fail;

	if (supplement_headers(ctx, state, state->is_valid_ip, &state->ip, false, NULL) < 0) trv = false;	// prioritize more relevant query wrt. timeout

	if (g_mta_header[0] != '\0' && !state->timer->timed_out && !state->got_mta_info		// unless disabled by empty qualifier (avoids name clash) - supplement except when already provided by earlier instance/server
	&& state->is_valid_peer && is_routeable_ip(&state->peer)
	&& (!state->is_valid_ip || state->ip.addr != state->peer.addr)) {			// suppress unless distinct - skip repeating info if same as Received
		if (supplement_headers(ctx, state, state->is_valid_peer, &state->peer, true, g_mta_header) < 0) trv = false;
	}
	if (!trv) goto fail;		// error somewhat meaningless here
	tret = true;
fail:
	return tret ? cleanup(ctx) : cleanup_fail(ctx);
}


static sfsistat mail_abort(SMFICTX *ctx)
{
	return cleanup(ctx);
}


static sfsistat mail_close(SMFICTX *ctx)
{
	return cleanup_done(ctx);
}


static void check_monotonic_clock()
{
#define NO_MONOTONIC_CLOCK \
	fprintf(stderr, "Warning: Monotonic clock is not available: using realtime " \
	"clock instead\n");

#define ENABLE_MONOTONIC_CLOCK \
	g_clock_id = CLOCK_MONOTONIC;

#define RUNTIME_ENABLE_MONOTONIC_CLOCK \
	if (sysconf(_SC_MONOTONIC_CLOCK) > 0) \
		ENABLE_MONOTONIC_CLOCK \
	else \
		NO_MONOTONIC_CLOCK

#ifdef _POSIX_MONOTONIC_CLOCK
#	if _POSIX_MONOTONIC_CLOCK == -1
		NO_MONOTONIC_CLOCK
#	else
#		if _POSIX_MONOTONIC_CLOCK == 0
			RUNTIME_ENABLE_MONOTONIC_CLOCK
#		else
			ENABLE_MONOTONIC_CLOCK
#		endif
#	endif
#else
	RUNTIME_ENABLE_MONOTONIC_CLOCK
#endif

#define DISABLE_MONOTONIC_CLOCK \
	if (g_clock_id != CLOCK_REALTIME) { \
		g_clock_id = CLOCK_REALTIME; \
		fprintf(stderr, "Warning: Monotonic clock is available but not useable " \
		"for pthread_condattr_setclock(): using realtime clock instead\n"); \
	}

#define RUNTIME_DISABLE_MONOTONIC_CLOCK \
	if (sysconf(_SC_CLOCK_SELECTION) <= 0) \
		DISABLE_MONOTONIC_CLOCK

#ifdef _POSIX_CLOCK_SELECTION
#	if _POSIX_CLOCK_SELECTION == -1
		DISABLE_MONOTONIC_CLOCK
#	else
#		if _POSIX_CLOCK_SELECTION == 0
			RUNTIME_DISABLE_MONOTONIC_CLOCK
#		endif
#	endif
#else
	RUNTIME_DISABLE_MONOTONIC_CLOCK
#endif
}


#define MAIN_FAIL(msg) \
	do { fprintf(stderr, msg); log_printf(msg); goto main_fail; } while (false)

#define MAIN_OUT_OF_MEMORY(ptr) \
	do { if ((ptr) == NULL) MAIN_FAIL("Fatal: Out of memory\n"); } while (false)

#define MAIN_PERROR_FAIL(msg) \
	do { \
		int errnum = errno; \
		perror(msg); \
		log_perror(msg, errnum); \
		goto main_fail; \
	} while (false)


static int pwmf_strtoui(const char *str, unsigned minimum)
{
	int	ret = -1;
	long	val;
	char	*ep = NULL;
	if (str == NULL) goto fail;
	errno = 0;
	val = strtol(str, &ep, 10);
	if (ep == NULL || *ep != '\0'
	|| ((val <= LONG_MIN || val >= LONG_MAX) && errno == ERANGE)
	|| (val == 0 && errno != 0)
	|| val >= INT_MAX || val < 0 || (unsigned)val < minimum)
		goto fail;
	ret = val;
fail:
	return ret;
}


static bool ignore_net(const char *str)
{
	bool		ret = false, warned = false;
	int		rv, cidr = 32;
	unsigned	mask, hbo, oldnum = g_ignore_count, tnum = oldnum + 1;
	char		buf[15 + 1 + 2 + 1], *ptr;
	struct ipnet	*parr;
	struct in_addr	in;

	if (str == NULL) { fprintf(stderr, "Fatal: unexpected NULL prefix.\n"); goto fail; }
	if (memccpy(buf, str, '\0', sizeof buf) == NULL) { fprintf(stderr, "Fatal: oversized prefix '%s'\n", str); goto fail; }
	if ((ptr = strchr(buf, '/')) == NULL) { fprintf(stderr, "Warning: missing CIDR for prefix '%s' - will assume %d\n", str, cidr); warned = true; }
	if (ptr != NULL && ((*ptr++ = '\0', (rv = pwmf_strtoui(ptr, 0)) < 0) || (cidr = rv) > 32)) { fprintf(stderr, "Fatal: invalid CIDR '%s' for prefix '%s'\n", ptr, str); goto fail; }
	parr = realloc(g_ignore_nets, tnum * sizeof *parr);
	if (parr == NULL) { fprintf(stderr, "Fatal: Out of memory\n"); goto fail; }
	g_ignore_nets = parr;
	g_ignore_count = tnum;
	parr += oldnum;
	parr->cidr = cidr;
	switch (rv = inet_pton(AF_INET, buf, &parr->net.addr)) {
	case 1:		// good
		break;
	case 0:		// try to parse legacy forms
		if (inet_aton(buf, &in) < 0) { fprintf(stderr, "Fatal: invalid network portion '%s' of prefix '%s'\n", buf, str); goto fail; }
		parr->net.addr = in.s_addr;
		fprintf(stderr, "Warning: unusual representation for network portion '%s' of prefix '%s'.\n", buf, str);
		warned = true;
		break;
	default:	// not possible
		if (rv < 0) { rv = errno; fprintf(stderr, "Fatal: IPv4 unsupported by system?!  ('%s' - errno = %d)\n", pw_strerror_p(rv, buf, sizeof buf), rv); goto fail; }
		fprintf(stderr, "Fatal: bad return value from inet_pton(3) - %d\n", rv);
		goto fail;
	}
	mask = cidr == 0 ? ~0 : (1 << (32 - cidr)) - 1;
	hbo = ntohl(parr->net.addr);
	if ((hbo & mask) != 0) { fprintf(stderr, "Warning: host portion '%s' of prefix '%s' is non-zero with CIDR %s - will clear\n", buf, str, ptr); warned = true; }
	parr->net.addr = htonl(hbo & ~mask);
	if (warned) fprintf(stderr, "Notice: interpreted '%s' as %s/%d\n", str, (buf[0] = '\0', inet_ntop(AF_INET, &parr->net.addr, buf, sizeof buf) == NULL ? "<NULL>" : buf), cidr);

	ret = true;
fail:
	return ret;
}


static void usage(void)
{
	fprintf(stderr, "Options:\n"
	"  -s socket_spec        Milter {unix|local}:/path/to/file or inet(6):port@host: defaults to %s\n"
	"  -f                    Run in foreground\n"
	"  -d                    Set libmilter debug level: foreground required if non-zero\n"
	"  -i pidfile            Write PID to pidfile: required if daemon\n"
	"  -l logfile            Write output to logfile: required if daemon\n"
	"  -u uid                Set UID and EUID to uid: defaults to current UID\n"
	"  -g gid                Set GID and EGID to gid: defaults to current GID\n"
	"  -t timeout_seconds    Timeout for queries in seconds: defaults to %i\n"
	"  -w pwhois_server      Specify an alternate pwhois server: defaults to %s\n"
	"  -p pwhois_port        Connect to given port: defaults to %s\n"
	"  -x header_prefix      Mail header prefix: defaults to %s\n"
	"  -y mta_header         MTA deliverer qualifier: defaults to %s (empty string will disable)\n"
	"  -n ip_network/cidr    Ignore prefix: if peer MTA or Received header match, then pass unchanged (may specify switch multiple times, one instance for each subnet)\n"
	, g_default_milter_socket_spec, g_default_timeout_sec
	, g_default_pwhois_host, g_default_pwhois_port
	, g_default_header_prefix, g_default_mta_header);
}


int main(int argc, char *argv[])
{
	struct smfiDesc filter = {
		.xxfi_name = "PWhois Milter v" PWM_VERSION,
		.xxfi_version = SMFI_VERSION,
		.xxfi_flags = SMFIF_ADDHDRS,
		.xxfi_connect = &mail_connect,
		.xxfi_helo = NULL,
		.xxfi_envfrom = &mail_envfrom,
		.xxfi_envrcpt = NULL,
		.xxfi_header = &mail_header,
		.xxfi_eoh = NULL,
		.xxfi_body = NULL,
		.xxfi_eom = &mail_eom,
		.xxfi_abort = &mail_abort,
		.xxfi_close = &mail_close,
		.xxfi_unknown = NULL,
		.xxfi_data = NULL,
		.xxfi_negotiate = NULL
	};
	sigset_t	sigset;
	struct sigaction sa;
	int		opt, retval, pipefd[2];
	FILE		*pidfile = NULL;
	uid_t		uid = getuid();
	gid_t		gid = getgid();
	pid_t		childpid;
	bool		run_in_foreground = false;

	while ((opt = getopt(argc, argv, "d:fg:i:l:n:p:s:t:u:w:x:y:")) != -1) {
		switch (opt) {
		case 'd':
			g_debug_level = strtoul(optarg, NULL, 10);
			break;
		case 'f':
			run_in_foreground = true;
			break;
		case 'g':
			gid = strtoul(optarg, NULL, 10);
			break;
		case 'i':
			pidfile = fopen(optarg, "w");
			if (pidfile == NULL)
				MAIN_PERROR_FAIL("Fatal: fopen(pidfile)");
			break;
		case 'l':
			g_logfilename = strdup(optarg);
			break;
		case 'n':
			if (!ignore_net(optarg)) goto main_fail;
			break;
		case 'p':
			g_pwhois_port = strdup(optarg);
			MAIN_OUT_OF_MEMORY(g_pwhois_port);
			g_is_default_pwhois_port = false;
			break;
		case 's':
			g_milter_socket_spec = strdup(optarg);
			MAIN_OUT_OF_MEMORY(g_milter_socket_spec);
			g_is_default_milter_socket_spec = false;
			break;
		case 't':
			g_timeout_sec = strtoul(optarg, NULL, 10);
			break;
		case 'u':
			uid = strtoul(optarg, NULL, 10);
			break;
		case 'w':
			g_pwhois_host = strdup(optarg);
			MAIN_OUT_OF_MEMORY(g_pwhois_host);
			g_is_default_pwhois_host = false;
			break;
		case 'x':
			g_header_prefix = strdup(optarg);
			MAIN_OUT_OF_MEMORY(g_header_prefix);
			g_is_default_header_prefix = false;
			break;
		case 'y':
			g_mta_header = strdup(optarg);
			MAIN_OUT_OF_MEMORY(g_mta_header);
			g_is_default_mta_header = false;
			break;
		default:
			usage();
			goto main_fail;
		}
	}
	if ((!run_in_foreground && (g_logfilename == NULL || pidfile == NULL
	|| g_debug_level > 0)) || g_timeout_sec == 0) {
		usage();
		goto main_fail;
	}

	if (setgid(gid) < 0 || setegid(gid) < 0) MAIN_PERROR_FAIL("Fatal: setgid() or setegid()");
	if (setuid(uid) < 0 || seteuid(uid) < 0) MAIN_PERROR_FAIL("Fatal: setuid() or seteuid()");
	if (g_logfilename != NULL) {
		g_logfile = fopen(g_logfilename, "a");
		if (g_logfile == NULL) MAIN_PERROR_FAIL("Fatal: fopen(logfile)");
	}
	if (g_is_default_pwhois_host) g_pwhois_host = g_default_pwhois_host;
	if (g_is_default_pwhois_port) g_pwhois_port = g_default_pwhois_port;
	if (g_is_default_milter_socket_spec) g_milter_socket_spec = g_default_milter_socket_spec;
	if (g_is_default_header_prefix) g_header_prefix = g_default_header_prefix;
	if (g_is_default_mta_header) g_mta_header = g_default_mta_header;

	check_monotonic_clock();

	if (smfi_setdbg(g_debug_level) != MI_SUCCESS) MAIN_FAIL("Fatal: smfi_setdbg() failed\n");

	if (smfi_register(filter) != MI_SUCCESS) MAIN_FAIL("Fatal: smfi_register() failed\n");

	if (smfi_setconn(g_milter_socket_spec) != MI_SUCCESS) MAIN_FAIL("Fatal: smfi_setconn() failed\n");

	sa.sa_handler = &sigstub;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGNAL_INTERRUPT, &sa, NULL) != 0) MAIN_PERROR_FAIL("Fatal: sigaction(SIGNAL_INTERRUPT)");
	sa.sa_handler = &signal_log_reopen;
	if (sigaction(SIGNAL_LOG_REOPEN, &sa, NULL) != 0) MAIN_PERROR_FAIL("Fatal: sigaction(SIGNAL_LOG_REOPEN)");
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGNAL_INTERRUPT);
	sigaddset(&sigset, SIGNAL_LOG_REOPEN);
	if (sigprocmask(SIG_UNBLOCK, &sigset, NULL) != 0) MAIN_PERROR_FAIL("Fatal: sigprocmask(SIG_UNBLOCK)");
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGPIPE);
	if (sigprocmask(SIG_BLOCK, &sigset, NULL) != 0) MAIN_PERROR_FAIL("Fatal: sigprocmask(SIG_BLOCK)");

	if (run_in_foreground) {
		if (pidfile != NULL) {
			if ((childpid = getpid()) < 0) MAIN_PERROR_FAIL("Fatal: getpid()");
			fprintf(pidfile, "%i\n", getpid());
			fclose(pidfile); pidfile = NULL;
		}
		if (g_logfile == NULL) g_logfile = stderr;

	} else {
		childpid = fork();
		if (childpid < 0) MAIN_PERROR_FAIL("Fatal: fork()");
		if (childpid > 0) { fprintf(pidfile, "%i\n", childpid); goto main_exit; }	// parent - finished
		fclose(pidfile); pidfile = NULL;
		if (setsid() < 0) { log_perror("Fatal: setsid()", errno); goto main_fail; }
		umask(0);
		if (chdir("/") != 0) log_perror("chdir('/')", errno);
		if (pipe(pipefd) != 0) log_perror("pipe(STDIN_FILENO)", errno);
		if (dup2(pipefd[0], STDIN_FILENO) < 0) log_perror("dup2(STDIN_FILENO)", errno);
		if (close(pipefd[0]) != 0 || close(pipefd[1]) != 0) log_perror("close(pipefd)", errno);
		if (pipe(pipefd) != 0) log_perror("pipe(STDOUT_FILENO)", errno);
		if (dup2(pipefd[1], STDOUT_FILENO) < 0) log_perror("dup2(STDOUT_FILENO)", errno);
		if (dup2(pipefd[1], STDERR_FILENO) < 0) log_perror("dup2(STDERR_FILENO)", errno);
		if (close(pipefd[0]) != 0 || close(pipefd[1]) != 0) log_perror("close(pipefd)", errno);
	}

	if (smfi_main() != MI_SUCCESS) { log_printf("Fatal: smfi_main() failed\n"); goto main_fail; }

main_exit:
	retval = EXIT_SUCCESS;

main_cleanup:
	if (pidfile != NULL) fclose(pidfile);
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGNAL_LOG_REOPEN);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
	free(g_logfilename);
	if (g_logfile != NULL) fclose(g_logfile);
	if (!g_is_default_pwhois_host) free(g_pwhois_host);
	if (!g_is_default_pwhois_port) free(g_pwhois_port);
	if (!g_is_default_milter_socket_spec) free(g_milter_socket_spec);
	if (!g_is_default_header_prefix) free(g_header_prefix);
	if (!g_is_default_mta_header) free(g_mta_header);
	if (g_ignore_nets != NULL) free(g_ignore_nets);
	return retval;

main_fail:
	retval = EXIT_FAILURE;
	goto main_cleanup;
}
