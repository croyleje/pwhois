/*
 *  pwhois_milter.c v1.2
 *
 *	Copyright 2013 VOSTROM Holdings, Inc.
 *  This file is part of the Distribution.  See the file COPYING for details.
 */

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
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

#define SIGNAL_LOG_REOPEN	SIGUSR1
#define SIGNAL_INTERRUPT	SIGUSR2

union ipv4 {
	uint32_t addr;
	uint8_t octet[4];
};

struct thread_timer;

struct filter_state {
	bool was_processed;
	union ipv4 ip;
	bool is_valid_ip;
	char *user_agent;
	char *from_domain;
	struct thread_timer *timer;
};

struct thread_timer {
	bool timed_out;
	timer_t timer_id;
	pthread_t thread;
	pthread_mutex_t is_valid_thread_lock;
	bool is_valid_thread;
	struct filter_state *state;
	struct thread_timer *prev;
	struct thread_timer *next;
};

struct getaddrinfo_params {
	struct filter_state *state;
	const char *host;
	const char *service;
	struct addrinfo *hints;
	struct addrinfo **result;
	pthread_cond_t cond;
	int retval;
	int errnum;
};

unsigned int g_debug_level = 0;
unsigned int g_default_timeout_sec = 5;
unsigned int g_timeout_sec;
char *g_default_pwhois_host = "whois.pwhois.org";
char *g_pwhois_host;
bool g_is_default_pwhois_host = true;
char *g_default_pwhois_port = "43";
char *g_pwhois_port;
bool g_is_default_pwhois_port = true;
char *g_default_milter_socket_spec = "inet:8472@localhost";
char *g_milter_socket_spec;
bool g_is_default_milter_socket_spec = true;
char *g_default_header_prefix = "X-PWhois-";
char *g_header_prefix;
bool g_is_default_header_prefix = true;

clockid_t g_clock_id = CLOCK_REALTIME;
pthread_mutex_t g_thread_timer_lock = PTHREAD_MUTEX_INITIALIZER;
struct thread_timer *g_thread_timer_list = NULL;

pthread_mutex_t g_logger_lock = PTHREAD_MUTEX_INITIALIZER;
char *g_logfilename = NULL;
FILE *g_logfile = NULL;
pthread_mutex_t g_strerror_lock = PTHREAD_MUTEX_INITIALIZER;

static void log_printf(const char *templ, ...)
{
	va_list ap;
	time_t tm;
	struct tm tms;
	char buf[1024];

	pthread_mutex_lock(&g_logger_lock);
	if (g_logfile != NULL) {
		time(&tm);
		gmtime_r(&tm, &tms);
		strftime(buf, sizeof(buf), "%b %Od %Y %H:%M:%S", &tms);
		fprintf(g_logfile, "%s", buf);
		va_start(ap, templ);
		vsnprintf(buf, sizeof(buf), templ, ap);
		va_end(ap);
		fprintf(g_logfile, ": %s", buf);
		fflush(g_logfile);
	}
	pthread_mutex_unlock(&g_logger_lock);
}

static void log_perror(char *str, int errnum)
{
	pthread_mutex_lock(&g_strerror_lock);
	log_printf("%s: %s\n", str, strerror(errnum));
	pthread_mutex_unlock(&g_strerror_lock);
}

#define LOG_OUT_OF_MEMORY log_printf("Error: Out of memory\n");

void *log_reopen(void *logger_lock)
{
	pthread_mutex_lock((pthread_mutex_t *)&logger_lock);
	if (g_logfile != NULL)
		fclose(g_logfile);
	g_logfile = fopen(g_logfilename, "a");
	pthread_mutex_unlock((pthread_mutex_t *)&logger_lock);
	return NULL;
}

void signal_log_reopen(int signum)
{
	pthread_t thread;

	if (signum != SIGNAL_LOG_REOPEN)
		return;
	if (pthread_create(&thread, NULL, &log_reopen, &g_logger_lock) == 0)
		pthread_detach(thread);
}

void sigstub(int signum)
{
	if (signum == SIGNAL_INTERRUPT)
		return;
}

void timer_expired(union sigval timer)
{
	struct thread_timer *node = timer.sival_ptr;

	pthread_mutex_lock(&g_thread_timer_lock);
	node->timed_out = true;
	pthread_mutex_lock(&node->is_valid_thread_lock);
	if (node->is_valid_thread)
		pthread_kill(node->thread, SIGNAL_INTERRUPT);
	pthread_mutex_unlock(&node->is_valid_thread_lock);
	pthread_mutex_unlock(&g_thread_timer_lock);
}

static void filter_state_cleanup(struct filter_state *state)
{
	free(state->user_agent);
	free(state->from_domain);
	pthread_mutex_lock(&g_thread_timer_lock);
	if (timer_delete(state->timer->timer_id) != 0)
		log_perror("Error: timer_delete()", errno);
	if (state->timer->prev == NULL)
		g_thread_timer_list = state->timer->next;
	else
		state->timer->prev->next = state->timer->next;
	if (state->timer->next != NULL)
		state->timer->next->prev = state->timer->prev;
	pthread_mutex_destroy(&state->timer->is_valid_thread_lock);
	free(state->timer);
	pthread_mutex_unlock(&g_thread_timer_lock);
}

static struct filter_state *filter_state_init(SMFICTX *ctx)
{
	struct filter_state *state;
	struct sigevent sev;
	struct itimerspec ts;

	state = smfi_getpriv(ctx);
	if (state == NULL) {
		state = malloc(sizeof(*state));
		if (state == NULL) {
			LOG_OUT_OF_MEMORY
			return NULL;
		}
	} else
		filter_state_cleanup(state);
	if (smfi_setpriv(ctx, state) != MI_SUCCESS) {
		free(state);
		return NULL;
	}
	state->was_processed = false;
	state->is_valid_ip = false;
	state->user_agent = NULL;
	state->from_domain = NULL;
	state->timer = malloc(sizeof(*state->timer));
	if (state->timer == NULL) {
		LOG_OUT_OF_MEMORY
		free(state);
		return NULL;
	}
	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_value.sival_ptr = state->timer;
	sev.sigev_notify_function = &timer_expired;
	sev.sigev_notify_attributes = NULL;
	if (timer_create(g_clock_id, &sev, &state->timer->timer_id) != 0) {
		log_perror("Error: timer_create()", errno);
		free(state->timer);
		free(state);
		return NULL;
	}
	state->timer->timed_out = false;
	ts.it_value.tv_sec = g_timeout_sec;
	ts.it_value.tv_nsec = ts.it_interval.tv_sec = ts.it_interval.tv_nsec = 0;
	if (timer_settime(state->timer->timer_id, 0, &ts, NULL) != 0) {
		log_perror("Error: timer_settime()", errno);
		timer_delete(state->timer->timer_id);
		free(state->timer);
		free(state);
		return NULL;
	}
	state->timer->thread = pthread_self();
	pthread_mutex_init(&state->timer->is_valid_thread_lock, NULL);
	state->timer->is_valid_thread = true;
	state->timer->state = state;
	pthread_mutex_lock(&g_thread_timer_lock);
	state->timer->prev = NULL;
	if (g_thread_timer_list != NULL)
		g_thread_timer_list->prev = state->timer;
	state->timer->next = g_thread_timer_list;
	g_thread_timer_list = state->timer;
	pthread_mutex_unlock(&g_thread_timer_lock);

	return state;
}

static int cleanup(SMFICTX *ctx)
{
	struct filter_state *state;

	state = smfi_getpriv(ctx);
	if (state != NULL) {
		filter_state_cleanup(state);
		free(state);
	}
	if (smfi_setpriv(ctx, NULL) != MI_SUCCESS)
		return SMFIS_ACCEPT;
	return SMFIS_CONTINUE;
}

static int cleanup_fail(SMFICTX *ctx)
{
	cleanup(ctx);
	return SMFIS_ACCEPT;
}

static struct filter_state *filter_state_begin(SMFICTX *ctx)
{
	struct filter_state *state = smfi_getpriv(ctx);
	if (state == NULL) {
		log_printf("Error: smfi_getpriv(ctx) returned NULL\n");
		return NULL;
	}
	if (state->timer->timed_out) {
		log_printf("Timed out; cleaning up\n");
		cleanup(ctx);
		return NULL;
	}
	pthread_mutex_lock(&state->timer->is_valid_thread_lock);
	state->timer->thread = pthread_self();
	state->timer->is_valid_thread = true;
	pthread_mutex_unlock(&state->timer->is_valid_thread_lock);
	return state;
}

static sfsistat filter_state_end(struct filter_state *state)
{
	pthread_mutex_lock(&state->timer->is_valid_thread_lock);
	state->timer->is_valid_thread = false;
	pthread_mutex_unlock(&state->timer->is_valid_thread_lock);
	return SMFIS_CONTINUE;
}

static int sendn(struct filter_state *state, int fd, const char *buf, size_t len)
{
	ssize_t retval;
	size_t sent = 0;

	if (len == 0)
		return 0;
	do {
		retval = send(fd, buf + sent, len - sent, 0);
		if (retval < 0) {
			if (errno == EINTR) {
				if (state->timer->timed_out) {
					log_printf("Timeout: send() aborted\n");
					return -1;
				}
				continue;
			}
			log_perror("Error: send()", errno);
			return retval;
		} else
			if (retval == 0)
				continue;
		sent += retval;
	} while (sent < len);

	return sent;
}

static bool sendstr(struct filter_state *state, int fd, const char *str)
{
	ssize_t len;

	len = strlen(str);
	return sendn(state, fd, str, len) == len;
}

static int recvn(struct filter_state *state, int fd, char *buf, size_t len)
{
	ssize_t retval;
	size_t received = 0;

	if (len == 0)
		return 0;
	do {
		retval = recv(fd, buf + received, len - received, 0);
		if (retval < 0) {
			if (errno == EINTR) {
				if (state->timer->timed_out) {
					log_printf("Timeout: recv() aborted\n");
					return -1;
				}
				continue;
			}
			log_perror("Error: recv()", errno);
			return retval;
		} else
			if (retval == 0)
				break;
		received += retval;
	} while (received < len);

	return received;
}

static char *recvstr(struct filter_state *state, int fd, size_t *sz)
{
	char *tmp, *response = NULL;
	size_t pos, len = 0;
	ssize_t retval;

	do {
		pos = len;
		len += 4096;
		tmp = realloc(response, len);
		if (tmp == NULL) {
			LOG_OUT_OF_MEMORY
			free(response);
			return NULL;
		}
		response = tmp;
		retval = recvn(state, fd, response + pos, len - pos);
		if (retval < 0) {
			free(response);
			return NULL;
		}
	} while (retval == (ssize_t)(len - pos));
	pos += retval;
	response = realloc(response, pos + 1);
	response[pos] = '\0';
	if (sz != NULL)
		*sz = pos;
	return response;
}

void *getaddrinfo_thread(void *arg)
{
	struct getaddrinfo_params *gaip = arg;

	do {
		gaip->retval = getaddrinfo(gaip->host, gaip->service,
		gaip->hints, gaip->result);
	} while (gaip->retval == EAI_SYSTEM && errno == EINTR
	&& !gaip->state->timer->timed_out);
	gaip->errnum = errno;
	pthread_cond_signal(&gaip->cond);
	return gaip;
}

static int connect_host(struct filter_state *state, const char *host, const char *service)
{
	struct addrinfo hints, *result = NULL, *rp;
	struct getaddrinfo_params gaip = {
		.state = state,
		.host = host,
		.service = service,
		.hints = &hints,
		.result = &result
	};
	pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	pthread_t thread;
	struct itimerspec its;
	struct timespec ts;
	int retval, fd;
	pthread_condattr_t attr;

	retval = pthread_condattr_init(&attr);
	if (retval != 0) {
		log_perror("Error: pthread_condaddr_init()", retval);
		return -1;
	}

/* posixoptions(7) */
#define PTHREAD_SET_CLOCK_ID \
	retval = pthread_condattr_setclock(&attr, g_clock_id); \
	if (retval != 0) { \
		log_perror("Error: pthread_condattr_setclock()", retval); \
		return -1; \
	}

#ifdef _POSIX_CLOCK_SELECTION
#	if _POSIX_CLOCK_SELECTION != -1
		PTHREAD_SET_CLOCK_ID
#	endif
#else
	PTHREAD_SET_CLOCK_ID
#endif

	retval = pthread_cond_init(&gaip.cond, &attr);
	if (retval != 0) {
		log_perror("Error: pthread_cond_init()", retval);
		return -1;
	}

	pthread_mutex_lock(&lock);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	retval = pthread_create(&thread, NULL, &getaddrinfo_thread, &gaip);
	if (retval != 0) {
		log_perror("Error: pthread_create()", retval);
		return -1;
	}
	if (timer_gettime(state->timer->timer_id, &its) != 0) {
		log_perror("Error: timer_gettime()", errno);
		return -1;
	}
	clock_gettime(g_clock_id, &ts);
	ts.tv_sec += its.it_value.tv_sec;
	ts.tv_nsec += its.it_value.tv_nsec;
	if (ts.tv_nsec > 1000000000) {
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000;
	}
	/* TODO: loop to protect against spurious wakeup */
	retval = pthread_cond_timedwait(&gaip.cond, &lock, &ts);
	pthread_cancel(thread);
	pthread_join(thread, NULL);
	pthread_mutex_unlock(&lock);
	pthread_condattr_destroy(&attr);
	pthread_cond_destroy(&gaip.cond);
	if (retval == ETIMEDOUT) {
		log_printf("Timeout: getaddrinfo() aborted\n");
		/* Resolve a race to access free()'d memory in timer_expired() */
		while (!state->timer->timed_out)
			continue;	/* pause() would introduce a small race */
		return -1;
	}
	retval = gaip.retval;
	errno = gaip.errnum;
	if (retval != 0) {
		if (retval == EAI_SYSTEM && errno == EINTR && state->timer->timed_out) {
			log_printf("Timeout: getaddrinfo() aborted\n");
			return -1;
		}
		log_printf("Error: getaddrinfo(): %s\n", gai_strerror(retval));
		return -1;
	}
	if (result == NULL) {
		log_printf("Error: getaddrinfo() returned a NULL result\n");
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		do {
			fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (fd < 0) {
				if (errno != EINTR)
					break;
				if (state->timer->timed_out) {
					log_printf("Timeout: socket() aborted\n");
					freeaddrinfo(result);
					return -1;
				}
			}
		} while (fd < 0 && errno == EINTR);
		if (fd < 0)
			continue;
		do {
			retval = connect(fd, rp->ai_addr, rp->ai_addrlen);
			if (retval < 0) {
				if (errno != EINTR)
					break;
				if (state->timer->timed_out) {
					log_printf("Timeout: connect() aborted\n");
					freeaddrinfo(result);
					return -1;
				}
			}
		} while (retval < 0 && errno == EINTR);
		if (retval == 0)
			break;
		close(fd);
	}
	freeaddrinfo(result);
	if (fd < 0 || retval < 0) {
		log_perror("Error: socket() or connect()", errno);
		return -1;
	}
	return fd;
}

sfsistat mail_envfrom(SMFICTX *ctx, char *argv[])
{
	struct filter_state *state;
	char *domain, *domain_end;
	size_t domain_len;

	state = filter_state_init(ctx);
	if (state == NULL)
		return SMFIS_ACCEPT;

	domain = strchr(argv[0], '@');
	if (domain == NULL)
		return filter_state_end(state);
	domain++;
	domain_end = strchr(domain, '>');

	if (domain_end == NULL)
		domain_len = strlen(domain);
	else
		domain_len = domain_end - domain;

	if (domain_len == 0)
		return filter_state_end(state);
	state->from_domain = malloc(domain_len + 1);
	if (state->from_domain == NULL) {
		LOG_OUT_OF_MEMORY
		return cleanup_fail(ctx);
	}
	memcpy(state->from_domain, domain, domain_len);
	state->from_domain[domain_len] = '\0';
	return filter_state_end(state);
}

static void regerror_print(int retval, regex_t *reg)
{
	size_t msgsize;
	char *msg;

	msgsize = regerror(retval, reg, NULL, 0);
	msg = malloc(msgsize);
	if (msg == NULL)
		LOG_OUT_OF_MEMORY
	else {
		regerror(retval, reg, msg, msgsize);
		log_printf("Error: regcomp() %s\n", msg);
		free(msg);
	}
}

static bool regex_match(char *pat, char *str, size_t n, regmatch_t *match)
{
	int retval;
	regex_t reg;

	retval = regcomp(&reg, pat, REG_EXTENDED | REG_ICASE) != 0;
	if (retval != 0) {
		regerror_print(retval, &reg);
		return false;
	}
	retval = regexec(&reg, str, n, match, 0);
	regfree(&reg);
	if (retval != 0) {
		match[0].rm_so = -1;
		match[0].rm_eo = -1;
	}
	return true;
}

static bool is_routeable_ip(const union ipv4 *ip)
{
	return ip->octet[0] != 0 && ip->octet[0] != 10 && ip->octet[0] != 127
	&& (ip->octet[0] != 169 || ip->octet[1] != 254)
	&& (ip->octet[0] != 172 || ip->octet[1] < 16 || ip->octet[1] > 31)
	&& (ip->octet[0] != 192 || ip->octet[1] != 168);
}

static bool ipv4_sscan_brackets(const char *str, union ipv4 *ip)
{
	return sscanf(str, "[%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"]",
	&ip->octet[0], &ip->octet[1], &ip->octet[2], &ip->octet[3]) == 4;
}

static bool ipv4_sscan(const char *str, union ipv4 *ip)
{
	return sscanf(str, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
	&ip->octet[0], &ip->octet[1], &ip->octet[2], &ip->octet[3]) == 4;
}

static bool parse_received(char *value, struct filter_state *state)
{
	char *rcvd_from, *rcvd_ip, *rcvd_ip_end, *rcvd_end, ch, chf;
	regmatch_t match[3];
	union ipv4 ip;
	bool retval, is_valid_ip = false;

	if (!regex_match("^[[:space:]]*from[[:space:]]+(.*)", value, 2, match))
		return false;
	if (match[0].rm_so < 0 || match[1].rm_so < 0)
		return true;
	rcvd_from = value + match[1].rm_so;
	rcvd_end = value + match[1].rm_eo;
	chf = *rcvd_end;
	*rcvd_end = '\0';
	if (!regex_match("^.*[[:space:]]+by", rcvd_from, 1, match))
		goto restore_fatal;
	if (!regex_match("^.*[[:space:]]+for", rcvd_from, 1, match + 1))
		goto restore_fatal;
	if (!regex_match("^.*[[:space:]]+with", rcvd_from, 1, match + 2))
		goto restore_fatal;
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
		if (match[0].rm_so < 0 || match[1].rm_so < 0)
			goto restore_ok;
		rcvd_ip_end = rcvd_ip + match[1].rm_eo;
		rcvd_ip += match[1].rm_so;
		ch = *rcvd_ip_end;
		*rcvd_ip_end = '\0';
		if (ipv4_sscan(rcvd_ip, &ip) && is_routeable_ip(&ip))
			is_valid_ip = true;
		*rcvd_ip_end = ch;
		rcvd_ip = rcvd_ip_end;
	} while (!is_valid_ip);
	if (is_valid_ip) {
		state->ip.addr = ip.addr;
		state->is_valid_ip = true;
	}
restore_ok:
	retval = true;
restore:
	*rcvd_end = chf;
	return retval;
restore_fatal:
	retval = false;
	goto restore;
}

sfsistat mail_header(SMFICTX *ctx, char *header, char *value)
{
	struct filter_state *state;
	union ipv4 ip;

	state = filter_state_begin(ctx);
	if (state == NULL)
		return SMFIS_ACCEPT;

	if (strncasecmp(header, g_header_prefix, strlen(g_header_prefix)) == 0) {
		state->was_processed = true;
		return filter_state_end(state);
	}
	if (strcasecmp(header, "X-Mailer") == 0
	|| strcasecmp(header, "User-Agent") == 0) {
		if (state->user_agent != NULL)
			return filter_state_end(state);
		for ( ; *value != '\0' && isspace(*value); value++)
			continue;
		state->user_agent = strdup(value);
		if (state->user_agent == NULL) {
			LOG_OUT_OF_MEMORY
			return cleanup_fail(ctx);
		}
		return filter_state_end(state);
	}

	if (strcasecmp(header, "Received") == 0) {
		if (!parse_received(value, state))
			return cleanup_fail(ctx);
		return filter_state_end(state);
	}

	if (strcasecmp(header, "X-Originating-IP") == 0
	&& (ipv4_sscan_brackets(value, &ip) || ipv4_sscan(value, &ip))
	&& is_routeable_ip(&ip)) {
		state->ip.addr = ip.addr;
		state->is_valid_ip = true;
	}
	return filter_state_end(state);
}

static bool add_header(SMFICTX *ctx, char *fieldname, char *field)
{
	char header[32];

	if (snprintf(header, sizeof(header), "%s%s", g_header_prefix, fieldname)
	>= (int)sizeof(header)) {
		log_printf("Error: Oversized field name: %s\n", fieldname);
		return false;
	}
	if (smfi_addheader(ctx, header, field) != MI_SUCCESS) {
		log_printf("Error adding field %s\n", fieldname);
		return false;
	}
	return true;
}

static bool add_header_field(SMFICTX *ctx, char *response, size_t rlen, char *fieldname)
{
	char ch, *field, *field_end;
	size_t fieldnamelen = strlen(fieldname);
	bool retval;

	if (fieldnamelen > rlen)
		return true;
	field = response;
	while (true) {
		field = strstr(field, fieldname);
		if (field == NULL)
			return true;
		if ((field == response || field[-1] == '\n')
		&& ((response + rlen - field - fieldnamelen) >= 1)
		&& field[fieldnamelen] == ':')
			break;
		field++;
	}
	field += fieldnamelen + 1;
	while (*field != '\0' && *field != '\n' && isspace(*field))	/* WSP */
		field++;
	if (field[0] == '\0' || field[0] == '\n'
	|| (field[0] == '-' && (field[1] == '\0' || field[1] == '\n'))
	|| (field[0] == 'N' && field[1] == 'U' && field[2] == 'L'
	&& field[3] == 'L' && (field[4] == '\0' || field[4] == '\n')))
		return true;
	for (field_end = field; *field_end != '\0' && *field_end != '\n'; field_end++)
		continue;
	ch = *field_end;
	*field_end = '\0';
	if (!add_header(ctx, fieldname, field))
		goto restore_fatal;

	retval = true;
restore:
	*field_end = ch;
	return retval;
restore_fatal:
	retval = false;
	goto restore;
}

static bool add_header_ip(SMFICTX *ctx, struct filter_state *state)
{
	char host[16];

	snprintf(host, sizeof(host), "%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8,
	state->ip.octet[0], state->ip.octet[1],
	state->ip.octet[2], state->ip.octet[3]);
	return add_header(ctx, "Origin", host);
}

sfsistat mail_eom(SMFICTX *ctx)
{
	struct filter_state *state;
	int fd = -1;
	char request[1024], *response = NULL;
	size_t responselen;

	state = filter_state_begin(ctx);
	if (state == NULL)
		return cleanup_fail(ctx);
	if (!state->is_valid_ip) {
		if (!state->was_processed
		&& !add_header(ctx, "Status", "No originator identified"))
			return cleanup_fail(ctx);
		return cleanup(ctx);
	}

	fd = connect_host(state, g_pwhois_host, g_pwhois_port);
	if (fd < 0)
		return cleanup_fail(ctx);
	if (snprintf(request, sizeof(request), "app=\"PWhois-Milter-v1.2 %s %s\"\n"
	"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n",
	state->from_domain == NULL ? "-unknown-" : state->from_domain,
	state->user_agent == NULL ? "-unknown-" : state->user_agent,
	state->ip.octet[0], state->ip.octet[1],
	state->ip.octet[2], state->ip.octet[3]) >= (int)sizeof(request)) {
		log_printf("Error: Request to PWhois is too large\n");
		goto failure;
	}
	if (!sendstr(state, fd, request))
		goto failure;
	response = recvstr(state, fd, &responselen);
	if (response == NULL)
		goto failure;
	if (strncasecmp(response, "Error", 5) == 0
	|| strncasecmp(response, "Sorry", 5) == 0) {
		log_printf("Warning: pwhois replied: %s", response);
		goto failure;
	}
	if (state->was_processed) {
		log_printf("Info: Message was already processed by a previous PWhois Milter\n");
		goto success;
	}
	if (!add_header_ip(ctx, state)
	|| !add_header_field(ctx, response, responselen, "Origin-AS")
	|| !add_header_field(ctx, response, responselen, "AS-Org-Name")
	|| !add_header_field(ctx, response, responselen, "Org-Name")
	|| !add_header_field(ctx, response, responselen, "Net-Name")
	|| !add_header_field(ctx, response, responselen, "City")
	|| !add_header_field(ctx, response, responselen, "Region")
	|| !add_header_field(ctx, response, responselen, "Country")
	|| !add_header_field(ctx, response, responselen, "Country-Code"))
		goto failure;
success:
	free(response);
	close(fd);
	return cleanup(ctx);
failure:
	if (response != NULL)
		free(response);
	if (fd >= 0)
		close(fd);
	return cleanup_fail(ctx);
}

sfsistat mail_close(SMFICTX *ctx)
{
	return cleanup(ctx);
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
	do { \
		fprintf(stderr, msg); \
		log_printf(msg); \
		goto main_fail; \
	} while (false)

#define MAIN_OUT_OF_MEMORY(ptr) \
	if ((ptr) == NULL) \
		MAIN_FAIL("Fatal: Out of memory\n")

#define MAIN_PERROR_FAIL(msg) \
	do { \
		perror(msg); \
		log_perror(msg, errno); \
		goto main_fail; \
	} while (false)

static void usage()
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
	"  -x header_prefix      Mail header prefix: defaults to %s\n",
	g_default_milter_socket_spec, g_default_timeout_sec,
	g_default_pwhois_host, g_default_pwhois_port, g_default_header_prefix);
}

int main(int argc, char *argv[])
{
	struct smfiDesc filter = {
		.xxfi_name = "PWhois Milter v1.2",
		.xxfi_version = SMFI_VERSION,
		.xxfi_flags = SMFIF_ADDHDRS,
		.xxfi_connect = NULL,
		.xxfi_helo = NULL,
		.xxfi_envfrom = &mail_envfrom,
		.xxfi_envrcpt = NULL,
		.xxfi_header = &mail_header,
		.xxfi_eoh = NULL,
		.xxfi_body = NULL,
		.xxfi_eom = &mail_eom,
		.xxfi_abort = &mail_close,
		.xxfi_close = &mail_close,
		.xxfi_unknown = NULL,
		.xxfi_data = NULL,
		.xxfi_negotiate = NULL
	};
	sigset_t sigset;
	struct sigaction sa;
	int opt, retval, pipefd[2];
	FILE *pidfile = NULL;
	uid_t uid = getuid();
	gid_t gid = getgid();
	pid_t childpid;
	bool run_in_foreground = false;

	g_timeout_sec = g_default_timeout_sec;
	while ((opt = getopt(argc, argv, "d:fg:i:l:p:s:t:u:w:x:")) != -1) {
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

	if (setgid(gid) < 0 || setegid(gid) < 0)
		MAIN_PERROR_FAIL("Fatal: setgid() or setegid()");
	if (setuid(uid) < 0 || seteuid(uid) < 0)
		MAIN_PERROR_FAIL("Fatal: setuid() or seteuid()");
	if (g_logfilename != NULL) {
		g_logfile = fopen(g_logfilename, "a");
		if (g_logfile == NULL)
			MAIN_PERROR_FAIL("Fatal: fopen(logfile)");
	}
	if (g_is_default_pwhois_host)
		g_pwhois_host = g_default_pwhois_host;
	if (g_is_default_pwhois_port)
		g_pwhois_port = g_default_pwhois_port;
	if (g_is_default_milter_socket_spec)
		g_milter_socket_spec = g_default_milter_socket_spec;
	if (g_is_default_header_prefix)
		g_header_prefix = g_default_header_prefix;

	check_monotonic_clock();

	if (smfi_setdbg(g_debug_level) != MI_SUCCESS)
		MAIN_FAIL("Fatal: smfi_setdbg() failed\n");

	if (smfi_register(filter) != MI_SUCCESS)
		MAIN_FAIL("Fatal: smfi_register() failed\n");

	if (smfi_setconn(g_milter_socket_spec) != MI_SUCCESS)
		MAIN_FAIL("Fatal: smfi_setconn() failed\n");

	sa.sa_handler = &sigstub;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGNAL_INTERRUPT, &sa, NULL) != 0)
		MAIN_PERROR_FAIL("Fatal: sigaction(SIGNAL_INTERRUPT)");
	sa.sa_handler = &signal_log_reopen;
	if (sigaction(SIGNAL_LOG_REOPEN, &sa, NULL) != 0)
		MAIN_PERROR_FAIL("Fatal: sigaction(SIGNAL_LOG_REOPEN)");
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGNAL_INTERRUPT);
	sigaddset(&sigset, SIGNAL_LOG_REOPEN);
	if (sigprocmask(SIG_UNBLOCK, &sigset, NULL) != 0)
		MAIN_PERROR_FAIL("Fatal: sigprocmask(SIG_UNBLOCK)");
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGPIPE);
	if (sigprocmask(SIG_BLOCK, &sigset, NULL) != 0)
		MAIN_PERROR_FAIL("Fatal: sigprocmask(SIG_BLOCK)");

	if (run_in_foreground) {
		if (pidfile != NULL) {
			fprintf(pidfile, "%i\n", getpid());
			fclose(pidfile);
			pidfile = NULL;
		}
		if (g_logfile == NULL)
			g_logfile = stderr;
	} else {
		childpid = fork();
		if (childpid < 0)
			MAIN_PERROR_FAIL("Fatal: fork()");
		if (childpid > 0) {
			fprintf(pidfile, "%i\n", childpid);
			goto main_exit;
		}
		fclose(pidfile);
		pidfile = NULL;
		if (setsid() < 0) {
			log_perror("Fatal: setsid()", errno);
			goto main_fail;
		}
		umask(0);
		chdir("/");
		pipe(pipefd);
		dup2(pipefd[0], STDIN_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		pipe(pipefd);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
	}

	if (smfi_main() != MI_SUCCESS) {
		log_printf("Fatal: smfi_main() failed\n");
		goto main_fail;
	}

main_exit:
	retval = EXIT_SUCCESS;
main_cleanup:
	if (pidfile != NULL)
		fclose(pidfile);
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGNAL_LOG_REOPEN);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
	free(g_logfilename);
	if (g_logfile != NULL)
		fclose(g_logfile);
	if (!g_is_default_pwhois_host)
		free(g_pwhois_host);
	if (!g_is_default_pwhois_port)
		free(g_pwhois_port);
	if (!g_is_default_milter_socket_spec)
		free(g_milter_socket_spec);
	if (!g_is_default_header_prefix)
		free(g_header_prefix);
	return retval;

main_fail:
	retval = EXIT_FAILURE;
	goto main_cleanup;
}
