/*
 *  pwhois_thread.c
 *
 *	Copyright 2007-13 VOSTROM Holdings, Inc.
 *  This file is part of the Distribution.  See the file COPYING for details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <pthread.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "pwhois_thread.h"
#include "timeformat.h"
#include "tst_malloc.h"
#include "patricia.h"
#include "IPV4.h"
#include "logger.h"

static patricia_tree_t * pTreeRoutes = NULL;
static struct route * all_route_records[2][2] = {{NULL, NULL}, {NULL, NULL}};
static unsigned int num_route_records[2][2] = {{0, 0}, {0, 0}};
static struct asn_count * asn_stats = NULL;
static unsigned int num_asn_stats = 0;
static struct asn * all_asn_records = NULL;
static struct asn_ll * asn_index[65536];
static unsigned int num_asn_records = 0;
static patricia_tree_t * pTreeNet = NULL;
static struct netblock * all_net_records = NULL;
static unsigned int num_net_records = 0;
static struct net_list * orgid_index_net[65536];
static struct org * all_org_records = NULL;
static unsigned int num_org_records = 0;
static struct org_list * orgid_index_org[65536];
static struct poc * all_poc_records = NULL;
static unsigned int num_poc_records = 0;
static struct poc_ll * pochandle_index[65536];
static patricia_tree_t * requests = NULL;

static time_t cacheDate=0;
static time_t lastTableUpdate=0;
static time_t pwhoisdStart=0;

static unsigned long all_counters[CNTR_MAX+1];
static pthread_mutex_t counter_locks[CNTR_MAX+1];

static int listen_port;
static unsigned int routeCounter = 0;
static unsigned int peersCounter = 0;
static int UseRouterFilter;
static uint32_t RouterFilter;

static int echoServerIsEnabled=0;	//for debugging

extern char reportpath[];
FILE * reportfile = NULL;
pthread_mutex_t reportfilelock = PTHREAD_MUTEX_INITIALIZER;

extern char VERSION[];
extern char PROGNAME[];
extern char COPYRIGHT[];

extern char ACLDB_EXPORT_FILENAME[];
extern char ASNDB_EXPORT_FILENAME[];
extern char GEODB_EXPORT_FILENAME[];
extern char NETDB_EXPORT_FILENAME[];
extern char ORGDB_EXPORT_FILENAME[];
extern char POCDB_EXPORT_FILENAME[];
extern char ROUDB_EXPORT_FILENAME[];

static int LOADING_STEP = 0;
static char * LOADING_STEP_NAME = NULL;
static unsigned long LOADING_STEP_SIZE = 0;
static unsigned long LOADING_STEP_CURR = 0;

#define MAX_BUFFER_LEN 1460
#define MILTER_MAX_QUERIES 1000000
#define FAIL2BAN_MAX_QUERIES 1000000

char text_help[]=
"Have no fear, help is here:\n"
"\n"
"DESCRIPTION\n"
"\n"
"    Prefix WhoIs displays the origin-as and other interesting information\n"
"    related to the most specific prefix currently advertised within the\n"
"    Internet's global routing table that corresponds to the IP address in\n"
"    your query.\n"
"    The only mandatory parameter is an IP address (optionally in CIDR notation,\n"
"    though pwhois assumes a /32 prefix). You may provide IP addresses with port\n"
"    numbers, though the port numbers will be removed and not returned to you in\n"
"    the result.\n"
"    You may optionally use the 'type' operator to change the display format\n"
"    between the native pwhois format, extended pwhois format, RPSL (RFC 2622),\n"
"    and the format used by Cymru (see www.cymru.com).\n"
"\n"
"STANDARD QUERY CONSTRUCTION\n"
"\n"
"    [type=pwhois|all|cymru|rpsl] <ip_address[/bits]>\n"
"\n"
"BULK QUERIES\n"
"\n"
"    Prefix WhoIs supports bulk queries using optional commands.  Only native and\n"
"    Cymru display types support bulk output.  When submitting a bulk query,\n"
"    simply make the term 'bulk' or 'begin' the first item/line sent in your\n"
"    query.  Then, you may optionally set the 'type' attribute and then enter\n"
"    one IP address per line.  To signify the end of your query, simply provide\n"
"    'quit' or 'end' as the last line of your query.\n"
"\n"
"EXAMPLES (single query)\n"
"\n"
"    '1.2.3.4'  or  'type=cymru 1.2.3.4'  or  'type=rpsl 1.2.3.4'\n"
"\n"
"EXAMPLES (bulk query)\n"
"\n"
"    begin                   begin\n"
"    type=cymru              1.2.3.4:80\n"
"    1.2.3.4                 5.6.7.8\n"
"    5.6.7.8/32              ...\n"
"    ...                     end\n"
"    end\n"
"\n"
"    The 'netcat' command may be used to submit bulk queries.  To do so, simply\n"
"    write your query to a file and concatenate the file contents into netcat\n"
"    like so:\n\n$ netcat <any-pwhois-server> 43 < ./ip_list.txt\n\n"
"    Our 'WhoB' whois client and our lightweight whois library also support\n"
"    bulk queries. Both are available at http://www.pwhois.org/\n\n"
"\n"
"HELP AND STATUS QUERIES\n"
"\n"
"    The 'help' command or '?' displays this help text.\n"
"\n"   
"    The 'version' command displays the PWHOIS server version and other details\n"
"    such as the date of the last routing table cache update and the number of\n"
"    prefixes in the global table.\n"
"\n"
"    The 'peers' command displays the (route server's) peer IP addresses from\n"
"    which the PWHOIS server is receiving data.\n"
"\n"
"    Another interesting query is the route view query which displays all the\n"
"    active routes in the global routing table cache (at the time of the last\n"
"    routing table update) for the prefix specified.\n"
"    A query with this feature may look like:\n"
"\n"
"        \"routeview prefix=1.2.3.4[/8]\"\n"
"\n"
"    Another form is to search by source-as, showing all the prefixes being\n"
"    announced by this source.\n"
"\n"
"        \"routeview source-as=12345\"\n"
"\n"
"    Similarly you can search for transit-as, showing all the prefixes that \n"
"    include the given ASN in the as-path.\n"
"\n"
"        \"routeview transit-as=12345\"\n"
"\n"
"    To search by AS organization name, issue:\n"
"\n"
"        \"routeview org-name=VOSTROM\"\n"
"\n"
"    One may list routes whose next hop is a particular host:\n"
"\n"
"        \"routview next-hop=IP\"\n"
"\n"
"    To list the number of prefixes announced by each AS and its associated\n"
"    country and organization name:\n"
"\n"
"        \"routeview as-count\"\n"
"\n"
"    Private and reserved ASNs are often found in the routing table.  In order\n"
"    to list the associated information, issue:\n"
"\n"
"        \"routeview as-private\"  or  \"routeview as-reserved\"\n"
"\n"
"    It is possible to observe route churn by viewing new and purged entries\n"
"    within a specified number of seconds since the routing table was last updated:\n"
"\n"
"        \"routeview new=3600\"  or  \"routeview purged=86400\"\n"
"\n"
"    Optionally, these commands may be augmented with two type qualifiers, best\n"
"    and all, which display only the best routes, or all the routes, respectively.\n"
"    If the type qualifier is not specified, the default behavior is 'best'.\n"
"\n"
"        [type=best|all]\n"
"\n"
"    A query with this feature may look like:\n"
"\n"
"        \"type=all routeview source-as=12345\"\n"
"     or \"type=best routeview prefix=1.2.3.4/24\"\n"
"\n"
"    Another command option, is to use to the netblock command to search for\n"
"    registration information for the source-as or organization you are looking for.\n"
"    Queries with this feature may look like:\n"
"\n"
"    \"netblock source-as=12345\"  or  \"netblock org-id=ABC-123\"\n"
"\n"
"    Registry information may be searched for and displayed directly (including\n"
"    contact information) by searching for the org-id, org-name, poc-handle,\n"
"    source-as, or email address.  Queries in this form may look as follows:\n"
"\n"
"    \"registry org-id=ABC-123\"  or  \"registry org-name=VOSTROM\"  or\n"
"    \"registry poc-handle=JKA-123\"  or  \"registry source-as=12345\" or\n"
"    \"registry email=username@example.com\"\n"
"\n"
"    Optionally, these commands may be augmented with the type qualifier 'all'\n"
"\n"
"        [type=all]\n"
"\n"
"    which display more information about the POC handles associated.\n"
"    If the type qualifier is not specified, the default behavior is to show only\n"
"    the handle.\n"
"\n"
"    A query with this feature may look like:\n"
"\n"
"        \"type=all registry source-as=12345\"\n"
"\n"
"SOFTWARE\n"
"\n"
"    You may download this source code and run your own PWHOIS server.  See\n"
"    http://www.pwhois.org/ for more details.\n"
"\n"
"DISCLAIMER\n"
"\n"
"    The PWHOIS service is provided for informational purposes only.  We do not\n"
"    guarantee its accuracy. By submitting a query, you agree to abide by the\n"
"    following terms of use: the compilation, repackaging, dissemination or\n"
"    other use of this data is expressly prohibited without our prior written\n"
"    consent.\n"
"    You agree not to use electronic processes that are automated to access or\n"
"    query this database except as reasonably necessary.  We reserve the right\n"
"    to restrict your access to this database in our sole discretion.\n"
"    We may restrict or terminate your access to this database for failure to\n"
"    abide by these terms of use.  We reserve the right to modify these terms\n"
"    at any time.\n\n"
"\n"
"AUTHORS AND THANKS\n\n"
"\n"
"    The PWHOIS service was created and is maintained by the following\n"
"    individuals and organizations, and wouldn't be possible without their time,\n"
"    energy, and on-going support. Thanks!\n\n"
"    Zachary Kanner, Victor Oppleman, Sergey Kondryukov, Robb Ballard,\n"
"    Rodney Joffe, Brett Watson, Troy Ablan, and Robert L. Thompson.\n"
"\n"
"QUESTIONS OR COMMENTS\n\n"
"\n"
"    Please send questions or comments about this service to\n"
"    pwhois-support@pwhois.org\n\n";
char text_extra_help[]=
"EXTRA SPECIAL COMMANDS\n"
"\n"
"    Another command for 'debugging' and other monitoring, is the statistics\n"
"    command.  A command of this form may look like this:\n"
"\n"
"        statistics\n";

static pthread_mutex_t mutexlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t reloadlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t dbreflock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t dbrefcond = PTHREAD_COND_INITIALIZER;
static int DatabaseIsLoaded = 0;
static int DatabaseReferencesCount = 0;

static int listen_sock;
static pwhois_thread_cb * threads_pool = NULL;
static int addrLength;
static int pool_length = 0;

static unsigned char * peers = NULL;
static char * asn_strings = NULL;
static char * net_strings = NULL;
static char * org_strings = NULL;
static char * poc_strings = NULL;
static char * route_strings = NULL;

static const char MSG_ACCESS_DENIED[]="Error: Unable to access server at this time - access is denied.\n";
static const char MSG_DATABASE_LOADING[]="Sorry, the FIB is currently reloading.  Please try again later.  Progress:";
static const char MSG_LIMIT_EXCEEDED[]="Error: Unable to perform lookup; Daily query limit exceeded.\nVisit http://pwhois.org/request/ to request a higher query limit.\n";
static const char MSG_INVALIDINPUT[]="Sorry, I don't like your input. You may ask for 'help'\n";
static const char MSG_NOT_AUTHORIZED[]="Sorry, this feature is not currently available. The server is either too busy, or you are not authorized\n";

static struct WHOIS_SOURCE_TYPE whois_sources[] = {
	{  WHOIS_SOURCE_UNKNOWN, "UNKNOWN" },
	{  WHOIS_SOURCE_ARIN, "ARIN" },
	{  WHOIS_SOURCE_RIPE, "RIPE" },
	{  WHOIS_SOURCE_APNIC, "APNIC" },
	{  WHOIS_SOURCE_JPNIC, "JPNIC" },
	{  WHOIS_SOURCE_AFRINIC, "AFRINIC" },
	{  WHOIS_SOURCE_LACNIC, "LACNIC" },
	{  WHOIS_SOURCE_TWNIC, "TWNIC" },
	{  WHOIS_SOURCE_KRNIC, "KRNIC" },
	{  WHOIS_SOURCE_IRINN, "IRINN" },
	{  WHOIS_SOURCE_JPIRR, "JPIRR" },
	{ -1, NULL } // Empty struct - end by convention
};

static char* GET_SOURCE_NAME(int id) {
	if (id < 0 || id > WHOIS_SOURCE_MAX)
		return whois_sources[0].name;
	return whois_sources[id].name;
}

int inc_loading_step(char * name, unsigned long sz)
{
	LOADING_STEP++;
	LOADING_STEP_NAME = name;
	LOADING_STEP_SIZE = sz;
	LOADING_STEP_CURR = 0;
	return LOADING_STEP;
}

unsigned long inc_loading_step_counter()
{
	LOADING_STEP_CURR++;
	return LOADING_STEP_CURR;
}

void EnableEchoServer()
{
	echoServerIsEnabled = 1;
}

ssize_t writen(int fd, const void *vptr, size_t n)
{
	size_t nleft;
	ssize_t nwritten;
	const char *ptr;
	
	ptr = vptr;
	nleft = n;
	while(nleft > 0)
	{
		if((nwritten = send(fd, ptr, nleft, 0)) <= 0)
		{
			if(nwritten < 0 && errno == EINTR)
				nwritten = 0;
			else
				return (-1);
		}
		nleft -= nwritten;
		ptr += nwritten;
	}
	return (n);
}

int writestr(pwhois_thread_cb * cb, const char * str)
{
	if (writen(cb->sock, str, strlen(str)) <= 0)
		return -1;
	return 0;
}

void incDBReference()
{
	pthread_mutex_lock(&dbreflock);
	DatabaseReferencesCount++;
	pthread_mutex_unlock(&dbreflock);
}

void decDBReference()
{
	pthread_mutex_lock(&dbreflock);
	DatabaseReferencesCount--;
	if(!DatabaseReferencesCount)
		pthread_cond_signal(&dbrefcond);
	pthread_mutex_unlock(&dbreflock);
}

void checkDBReferenceAndLock()
{
	pthread_mutex_lock(&dbreflock);
	while(DatabaseReferencesCount)
		pthread_cond_wait(&dbrefcond,&dbreflock);
	DatabaseIsLoaded=0;
	pthread_mutex_unlock(&dbreflock);
}

int incDBReferenceAndLock(pwhois_thread_cb * cb)
{
	char response[256];

	incDBReference();
	if (!DatabaseIsLoaded) {
		sprintf(response, "%s step: %d(%s), counter: %lu/%lu\n", MSG_DATABASE_LOADING, LOADING_STEP, LOADING_STEP_NAME, LOADING_STEP_CURR, LOADING_STEP_SIZE);
		decDBReference();
		writestr(cb, response);
		return -1;
	}
	return 0;
}

void save_listen_port(int port)
{
    listen_port=port;
}

time_t getCacheDate()
{
	return cacheDate;
}

static int limit_max_queries=DEFAULT_MAX_QUERIES;

int getQueriesLimit()
{
    return limit_max_queries;
}

int setQueriesLimit(int limit)
{
    limit_max_queries=limit;
    return limit_max_queries;
}

unsigned long incCounter(int idx)
{
    unsigned long count;
    if(idx<CNTR_MIN || idx>CNTR_MAX)
        return 0;
    pthread_mutex_lock(&counter_locks[idx]);
    count = (++(all_counters[idx]));
    pthread_mutex_unlock(&counter_locks[idx]);
    return count;
}

unsigned long getCounter(int idx)
{
    unsigned long count;
    if(idx<CNTR_MIN || idx>CNTR_MAX)
        return 0;
    pthread_mutex_lock(&counter_locks[idx]);
    count = all_counters[idx];
    pthread_mutex_unlock(&counter_locks[idx]);
    return count;
}

void initialize_all_counters()
{
	int i;
	for(i=0;i<=CNTR_MAX;i++) {
		all_counters[i]=0;
        pthread_mutex_init(&counter_locks[i], NULL);
    }
}

unsigned long decCounter(int idx)
{
    unsigned long count;
    if(idx<CNTR_MIN || idx>CNTR_MAX)
        return 0;
    pthread_mutex_lock(&counter_locks[idx]);
	if(!all_counters[idx])
	{
        pthread_mutex_unlock(&counter_locks[idx]);
		log_printf(0, "Strange decrement of counter #%d\n",idx);
		return 0;
	}
    count = (--(all_counters[idx]));
    pthread_mutex_unlock(&counter_locks[idx]);
    return count;
}

void SetupFilterParameters(int use_filt, uint32_t filt_router_id)
{
	UseRouterFilter=use_filt;
	RouterFilter=filt_router_id;
}

/* http://burtleburtle.net/bob/hash/evahash.html */
/* The mixing step */
#define mix(a, b, c)				\
{									\
  a -= b;  a -= c;  a ^= c >> 13;	\
  b -= c;  b -= a;  b ^= a << 8;	\
  c -= a;  c -= b;  c ^= b >> 13;	\
  a -= b;  a -= c;  a ^= c >> 12;	\
  b -= c;  b -= a;  b ^= a << 16;	\
  c -= a;  c -= b;  c ^= b >> 5;	\
  a -= b;  a -= c;  a ^= c >> 3;	\
  b -= c;  b -= a;  b ^= a << 10;	\
  c -= a;  c -= b;  c ^= b >> 15;	\
}

static inline uint32_t hck(register uint_fast8_t c, register uint_fast8_t bit)
{
	if (c >= 'A' && c <= 'Z')
		c |= bit;
	return c;
}

static inline uint32_t hckw(register const uint8_t *k, register uint_fast8_t bit)
{
	return hck(k[0], bit) + (hck(k[1], bit) << 8) + (hck(k[2], bit) << 16) + (hck(k[3], bit) << 24);
}

/* Arguments: key, length of key in bytes, previous hash or arbitrary value */
static uint_fast16_t hashstringto16(const char *str, register uint_fast8_t bit)
{
	register const uint8_t *k = (const uint8_t *)str;
	register uint32_t	a,b,c;						/* the internal state */
	unsigned int		len, length = strlen(str);	/* how many key bytes still need mixing */

	/* Set up the internal state */
	len = length;
	a = b = 0x9e3779b9;		/* the golden ratio; an arbitrary value */
	c = 0;					/* variable initialization of internal state */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += hckw(k, bit);	k += 4;
		b += hckw(k, bit);	k += 4;
		c += hckw(k, bit);	k += 4;
		mix(a, b, c);
		len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += length;
	switch (len)			/* all the case statements fall through */
	{
	case 11: c += hck(k[10], bit) << 24;
	case 10: c += hck(k[9], bit) << 16;
	case 9 : c += hck(k[8], bit) << 8;
		/* the first byte of c is reserved for the length */
	case 8 : b += hck(k[7], bit) << 24;
	case 7 : b += hck(k[6], bit) << 16;
	case 6 : b += hck(k[5], bit) << 8;
	case 5 : b += hck(k[4], bit);
	case 4 : a += hck(k[3], bit) << 24;
	case 3 : a += hck(k[2], bit) << 16;
	case 2 : a += hck(k[1], bit) << 8;
	case 1 : a += hck(k[0], bit);
		/* case 0: nothing left to add */
	}
	mix(a, b, c);
	/*-------------------------------------------- report the result */
	return (c >> 16) ^ (c & 0xffff);
}

static uint_fast16_t hash32to16(uint32_t n)
{
	uint_fast8_t s = 16 - 1;
	uint_fast16_t r, v, l = n & 0xffff;
	for (r = 0, v = l >> 1; v; v >>= 1) {
		r <<= 1;
		r |= v & 1;
		s--;
	}
	r <<= s;	// finish bit reversal of remaining zero bits
	v = (n >> 16) ^ l;
	return v ^ (v >> 4) ^ r;
}

/*----------------------------------------- Fast load -----------------------------------------*/

void loadASNDatabase_fromFile(char * fname)
{
	FILE * inpf;
	uint32_t * base, * ptr;
	uint32_t recCount, i, ruint;
	size_t stringArraySize;
	struct stat fileinfo;
	uint_fast16_t hash;
	struct asn_ll * curr;
	struct asn * node;

	if (all_asn_records != NULL)
		return;
	inpf = fopen(fname, "rb");
	if (inpf == NULL) {
		log_printf(0, "Can't open import file %s\n", fname);
		return;
	}
	fstat(fileno(inpf), &fileinfo);
	ptr = base = mmap(NULL, fileinfo.st_size, PROT_READ, MAP_PRIVATE, fileno(inpf), 0);
	if (base == MAP_FAILED) {
		log_printf(0, "mmap() of %s failed!\n", fname);
		fclose(inpf);
		return;
	}
	posix_madvise(base, fileinfo.st_size, POSIX_MADV_SEQUENTIAL);
	num_asn_records = recCount = ntohl(*ptr++);
	stringArraySize = fileinfo.st_size - sizeof(recCount) - recCount * 14 * sizeof(ruint);
	node = all_asn_records = tst_malloc(recCount * sizeof(*node));
	asn_strings = tst_malloc(stringArraySize);
	inc_loading_step("ASN", recCount);
	for (i = 0; i < recCount; i++, node++) {
		ruint = ntohl(*ptr++);
		hash = hash32to16(ruint);	// ASNs in asn table appear only once
		curr = tst_malloc(sizeof(*curr));	// Assumes ASN is loaded before Routes!
		curr->next = asn_index[hash];
		asn_index[hash] = curr;
		curr->as = node;
		curr->list = NULL;
        curr->transit_list = NULL;
		curr->asn = ruint;
		node->asn = ruint;
		node->source = ntohl(*ptr++);
		node->createDate = ntohl(*ptr++);
		node->modifyDate = ntohl(*ptr++);
		node->asHandle = asn_strings + ntohl(*ptr++);
		node->org_id = asn_strings + ntohl(*ptr++);
		node->asName = asn_strings + ntohl(*ptr++);
		node->registerDate = asn_strings + ntohl(*ptr++);
		node->updateDate = asn_strings + ntohl(*ptr++);
		node->adminHandle = asn_strings + ntohl(*ptr++);
		node->techHandle = asn_strings + ntohl(*ptr++);
		node->asOrgName = asn_strings + ntohl(*ptr++);
		node->comment = asn_strings + ntohl(*ptr++);
		node->mailbox = asn_strings + ntohl(*ptr++);
		inc_loading_step_counter();
	}
	inc_loading_step("ASN (STRINGS)", 1);
	memcpy(asn_strings, ptr, stringArraySize);
	posix_madvise(base, fileinfo.st_size, POSIX_MADV_DONTNEED);
	munmap(base, fileinfo.st_size);
	fclose(inpf);
}

void ClearASNDatabase_fromFile()
{
	if (all_asn_records == NULL)
		return;
	tst_free(all_asn_records);
	all_asn_records = NULL;
	num_asn_records = 0;
	tst_free(asn_strings);
	asn_strings = NULL;
	// ClearRoutesDatabase_fromFile() frees the asn_index[65536] linked lists since it needs to free the attached route lists
}

unsigned int range_to_cidr(uint64_t startip, uint64_t endip)
{
	unsigned int shift;
	uint32_t bit;
	
	for (shift = 0, bit = 1; (startip | bit) <= endip && shift < 32 && (startip & bit) == 0; shift++, bit <<= 1)
		startip |= bit;
	return 32 - shift;
}

void loadNetDatabase_fromFile(char * fname)
{
	FILE * inpf;
	struct stat fileinfo;
	uint32_t * base, * ptr;
	uint32_t recCount, ruint, i, node_range, curr_range;
	size_t stringArraySize;
	struct netblock * node, * curr;
	uint64_t startip, endip;
	prefix_t * newprefix;
	patricia_node_t * pnode;
	unsigned int cidr, n;
	char host[20];
	uint_fast16_t hash;
	struct net_list * list;

	if (pTreeNet != NULL)
		return;
	inpf = fopen(fname, "rb");
	if (inpf == NULL) {
		log_printf(0, "Can't open import file %s\n", fname);
		return;
	}
	fstat(fileno(inpf), &fileinfo);
	ptr = base = mmap(NULL, fileinfo.st_size, PROT_READ, MAP_PRIVATE, fileno(inpf), 0);
	if (base == MAP_FAILED) {
		log_printf(0, "mmap() of %s failed!\n", fname);
		fclose(inpf);
		return;
	}
	posix_madvise(base, fileinfo.st_size, POSIX_MADV_SEQUENTIAL);
	num_net_records = recCount = ntohl(*ptr++);
	stringArraySize = fileinfo.st_size - sizeof(recCount) - recCount * 17 * sizeof(ruint);
	node = all_net_records = tst_malloc(recCount * sizeof(*node));
	net_strings = tst_malloc(stringArraySize);
	pTreeNet = New_Patricia(32);
	inc_loading_step("Net", recCount);
	for (i = 0; i < recCount; i++, node++) {
		node->network = startip = ntohl(*ptr++);
		node->enetrange = endip = ntohl(*ptr++);
		node->createDate = ntohl(*ptr++);
		node->modifyDate = ntohl(*ptr++);
		node->netType = ntohl(*ptr++);
		node->source = ntohl(*ptr++);
		node->status = ntohl(*ptr++);
		node->netName = net_strings + ntohl(*ptr++);
		node->registerDate = net_strings + ntohl(*ptr++);
		node->updateDate = net_strings + ntohl(*ptr++);
		node->nocHandle = net_strings + ntohl(*ptr++);
		node->abuseHandle = net_strings + ntohl(*ptr++);
		node->techHandle = net_strings + ntohl(*ptr++);
		node->org_id = net_strings + ntohl(*ptr++);
		node->netHandle = net_strings + ntohl(*ptr++);
		node->orgName = net_strings + ntohl(*ptr++);
		node->mailbox = net_strings + ntohl(*ptr++);
		while (startip <= endip) {
			cidr = range_to_cidr(startip, endip);
			ruint = htonl(startip);
			newprefix = New_Prefix(AF_INET, &ruint, cidr);
			pnode = patricia_lookup(pTreeNet, newprefix);
			Deref_Prefix(newprefix);
			if (pnode->data == NULL)
				pnode->data = node;
			else {
				curr = pnode->data;
				curr_range = curr->enetrange - curr->network;
				node_range = node->enetrange - node->network;
				if (node_range < curr_range || (node_range == curr_range && (node->modifyDate > curr->modifyDate || (node->modifyDate == curr->modifyDate && node->status > curr->status))))
					pnode->data = node;
				else
					log_printf(5, "Prefix already in tree: %s/%d\n", ipv4_decimal_to_quaddot(startip, host, 20), cidr);
			}
			startip = (startip | ((1ULL << (32 - cidr)) - 1)) + 1;
		}
		inc_loading_step_counter();
	}
	inc_loading_step("Net (STRINGS)", 1);
	memcpy(net_strings, ptr, stringArraySize);
	posix_madvise(base, fileinfo.st_size, POSIX_MADV_DONTNEED);
	munmap(base, fileinfo.st_size);
	inc_loading_step("Net (INDEX)", 1);
	node = all_net_records;
	for (i = 0; i < num_net_records; i++, node++) {
		hash = hashstringto16(node->org_id, CASE_INSENSITIVE);
		list = orgid_index_net[hash];
		if (list == NULL) {
			n = 16;
			list = orgid_index_net[hash] = tst_malloc(sizeof *list + n * sizeof list->net[0]);
			list->size = n;
			n = list->num = 1;
		} else {
			n = ++list->num;
			if (n >= list->size) {
				list->size *= 2;
				list = orgid_index_net[hash] = tst_realloc(list, sizeof *list + list->size * sizeof list->net[0]);
			}
		}
		list->net[n - 1] = node;
	}
	fclose(inpf);
}

static void destroystub(){}

void ClearNetDatabase_fromFile()
{
	unsigned int i;

	if (pTreeNet == NULL)
		return;
	tst_free(all_net_records);
	all_net_records = NULL;
	num_net_records = 0;
	tst_free(net_strings);
	net_strings = NULL;
	Destroy_Patricia(pTreeNet, destroystub);
	pTreeNet = NULL;
	for (i = 0; i <= 65535; i++)
		if (orgid_index_net[i] != NULL) {
			tst_free(orgid_index_net[i]);
			orgid_index_net[i] = NULL;
		}
}

void AddOrgHandleToPOC(char * handle, uint_fast16_t hash, struct org * node)
{
	struct poc_ll * poc_prev, * poc_curr;
	struct org_list * list;
	unsigned int n = 0;

	poc_prev = NULL;
	poc_curr = pochandle_index[hash];
	while (poc_curr != NULL && strcmp(handle, poc_curr->pocHandle) != 0) {
		poc_prev = poc_curr;
		poc_curr = poc_curr->next;
	}
	if (poc_curr == NULL) {
		poc_curr = tst_malloc(sizeof(*poc_curr));
		poc_curr->next = pochandle_index[hash];
		pochandle_index[hash] = poc_curr;
		poc_curr->poc = NULL;
		poc_curr->orglist = NULL;
		poc_curr->pocHandle = handle;
	} else if (poc_prev != NULL) {
		poc_prev->next = poc_curr->next;
		poc_curr->next = pochandle_index[hash];
		pochandle_index[hash] = poc_curr;
	}
	list = poc_curr->orglist;
	if (list != NULL)
		for (n = 0; n < list->num && list->org[n]->id != node->id; n++)
			continue;
	if (list == NULL) {
		n = 4;
		list = poc_curr->orglist = tst_malloc(sizeof *list + n * sizeof list->org[0]);
		list->size = n;
		n = list->num = 1;
		list->org[n - 1] = node;
	} else if (n == list->num) {
		list->num = ++n;
		if (n >= list->size) {
			list->size *= 2;
			list = poc_curr->orglist = tst_realloc(list, sizeof *list + list->size * sizeof list->org[0]);
		}
		list->org[n - 1] = node;
	}
}

void AddAllOrgHandlesToPOC(struct org * node)
{
	unsigned int i, j;
	uint_fast16_t hash[4];
	char * handle[4];

	handle[0] = node->adminHandle;
	handle[1] = node->nocHandle;
	handle[2] = node->abuseHandle;
	handle[3] = node->techHandle;

	for (i = 0; i < sizeof handle / sizeof *handle; i++) {
		hash[i] = 0;
		if (handle[i][0] == '\0')
			continue;
		hash[i] = hashstringto16(handle[i], CASE_SENSITIVE);
		for (j = 0; j < i; j++)	
			if (hash[j] == hash[i] && handle[j][0] != '\0')
				break;
		if (j < i)
			continue;
		AddOrgHandleToPOC(handle[i], hash[i], node);
	}
}

void loadOrgDatabase_fromFile(char * fname)
{
	FILE * inpf;
	struct stat fileinfo;
	uint32_t * base, * ptr;
	uint32_t recCount, i, j, ruint;
	size_t stringArraySize;
	uint_fast16_t hash;
	struct org * node;
	struct org_list * list;
	unsigned int n;

	inpf = fopen(fname, "rb");
	if (inpf == NULL) {
		log_printf(0, "Can't open import file %s\n", fname);
		return;
	}
	fstat(fileno(inpf), &fileinfo);
	ptr = base = mmap(NULL, fileinfo.st_size, PROT_READ, MAP_PRIVATE, fileno(inpf), 0);
	if (base == MAP_FAILED) {
		log_printf(0, "mmap() of %s failed!\n", fname);
		fclose(inpf);
		return;
	}
	posix_madvise(base, fileinfo.st_size, POSIX_MADV_SEQUENTIAL);
	num_org_records = recCount = ntohl(*ptr++);
	stringArraySize = fileinfo.st_size - sizeof(recCount) - recCount * 25 * sizeof(ruint);
	node = all_org_records = tst_malloc(recCount * sizeof(*node));
	org_strings = tst_malloc(stringArraySize);
	inc_loading_step("Org", recCount);
	for (i = 0; i < recCount; i++, node++) {
		node->id = ntohl(*ptr++);
		node->canAllocate = ntohl(*ptr++);
		node->source = ntohl(*ptr++);
		node->createDate = ntohl(*ptr++);
		node->modifyDate = ntohl(*ptr++);
		node->org_id = org_strings + ntohl(*ptr++);
		node->orgName = org_strings + ntohl(*ptr++);
		for (j = 0; j < 6; j++)
			node->street[j] = org_strings + ntohl(*ptr++);
		node->city = org_strings + ntohl(*ptr++);
		node->state = org_strings + ntohl(*ptr++);
		node->country = org_strings + ntohl(*ptr++);
		node->postalCode = org_strings + ntohl(*ptr++);
		node->registerDate = org_strings + ntohl(*ptr++);
		node->updateDate = org_strings + ntohl(*ptr++);
		node->adminHandle = org_strings + ntohl(*ptr++);
		node->nocHandle = org_strings + ntohl(*ptr++);
		node->abuseHandle = org_strings + ntohl(*ptr++);
		node->techHandle = org_strings + ntohl(*ptr++);
		node->referralServer = org_strings + ntohl(*ptr++);
		node->comment = org_strings + ntohl(*ptr++);
		inc_loading_step_counter();
	}
	inc_loading_step("Org (STRINGS)", 1);
	memcpy(org_strings, ptr, stringArraySize);
	posix_madvise(base, fileinfo.st_size, POSIX_MADV_DONTNEED);
	munmap(base, fileinfo.st_size);
	inc_loading_step("Org (INDEX)", 1);
	node = all_org_records;
	for (i = 0; i < recCount; i++, node++) {
		hash = hashstringto16(node->org_id, CASE_INSENSITIVE);
		list = orgid_index_org[hash];
		if (list == NULL) {
			n = 16;
			list = orgid_index_org[hash] = tst_malloc(sizeof *list + n * sizeof list->org[0]);
			list->size = n;
			n = list->num = 1;
		} else {
			n = ++list->num;
			if (n >= list->size) {
				list->size *= 2;
				list = orgid_index_org[hash] = tst_realloc(list, sizeof *list + list->size * sizeof list->org[0]);
			}
		}
		list->org[n - 1] = node;
		AddAllOrgHandlesToPOC(node);
	}
	fclose(inpf);
}

void ClearOrgDatabase_fromFile()
{
	unsigned int i;
	struct poc_ll * poc_curr, * poc_next;

	if (all_org_records == NULL)
		return;
	tst_free(all_org_records);
	all_org_records = NULL;
	num_org_records = 0;
	tst_free(org_strings);
	org_strings = NULL;
	for (i = 0; i <= 65535; i++)
		if (orgid_index_org[i] != NULL) {
			tst_free(orgid_index_org[i]);
			orgid_index_org[i] = NULL;
		}
	for (i = 0; i <= 65535; i++) {
		poc_curr = pochandle_index[i];
		while (poc_curr != NULL) {
			if (poc_curr->orglist != NULL)
				tst_free(poc_curr->orglist);
			poc_next = poc_curr->next;
			tst_free(poc_curr);
			poc_curr = poc_next;
		}
		pochandle_index[i] = NULL;
	}
}

void loadPOCDatabase_fromFile(char * fname)
{
	FILE * inpf;
	uint32_t * base, * ptr;
	uint32_t recCount, i, j, ruint;
	size_t stringArraySize;
	struct stat fileinfo;
	uint_fast16_t hash;
	struct poc * node;
	struct poc_ll * curr;

	inpf = fopen(fname, "rb");
	if (inpf == NULL) {
		log_printf(0, "Can't open import file %s\n", fname);
		return;
	}
	fstat(fileno(inpf), &fileinfo);
	ptr = base = mmap(NULL, fileinfo.st_size, PROT_READ, MAP_PRIVATE, fileno(inpf), 0);
	if (base == MAP_FAILED) {
		log_printf(0, "mmap() of %s failed!\n", fname);
		fclose(inpf);
		return;
	}
	posix_madvise(base, fileinfo.st_size, POSIX_MADV_SEQUENTIAL);
	num_poc_records = recCount = ntohl(*ptr++);
	stringArraySize = fileinfo.st_size - sizeof(recCount) - recCount * 24 * sizeof(ruint);
	poc_strings = tst_malloc(stringArraySize);
	node = all_poc_records = tst_malloc(recCount * sizeof(*node));
	inc_loading_step("POC", recCount);
	for (i = 0; i < recCount; i++, node++) {
		node->isrole = ntohl(*ptr++);
		node->source = ntohl(*ptr++);
		node->createDate = ntohl(*ptr++);
		node->modifyDate = ntohl(*ptr++);
		node->registerDate = poc_strings + ntohl(*ptr++);
		node->updateDate = poc_strings + ntohl(*ptr++);
		node->pocHandle = poc_strings + ntohl(*ptr++);
		node->firstName = poc_strings + ntohl(*ptr++);
		node->middleName = poc_strings + ntohl(*ptr++);
		node->lastName = poc_strings + ntohl(*ptr++);
		node->roleName = poc_strings + ntohl(*ptr++);
		for (j = 0; j < 6; j++)
			node->street[j] = poc_strings + ntohl(*ptr++);
		node->city = poc_strings + ntohl(*ptr++);
		node->state = poc_strings + ntohl(*ptr++);
		node->country = poc_strings + ntohl(*ptr++);
		node->postalCode = poc_strings + ntohl(*ptr++);
		node->officePhone = poc_strings + ntohl(*ptr++);
		node->mailbox = poc_strings + ntohl(*ptr++);
		node->comment = poc_strings + ntohl(*ptr++);
		inc_loading_step_counter();
	}
	inc_loading_step("POC (STRINGS)", 1);
	memcpy(poc_strings, ptr, stringArraySize);
	posix_madvise(base, fileinfo.st_size, POSIX_MADV_DONTNEED);
	munmap(base, fileinfo.st_size);
	inc_loading_step("POC (INDEX)", 1);
	node = all_poc_records;
	for (i = 0; i < recCount; i++, node++) {
		hash = hashstringto16(node->pocHandle, CASE_SENSITIVE);
		curr = tst_malloc(sizeof(*curr));	// Assumes POC is loaded before Org!
		curr->next = pochandle_index[hash];
		pochandle_index[hash] = curr;
		curr->poc = node;
		curr->orglist = NULL;
		curr->pocHandle = node->pocHandle;
		node->poc = curr;
	}
	fclose(inpf);
}

void ClearPOCDatabase_fromFile()
{
	if (all_poc_records == NULL)
		return;
	tst_free(all_poc_records);
	all_poc_records = NULL;
	num_poc_records = 0;
	tst_free(poc_strings);
	poc_strings = NULL;
	// ClearOrgDatabase_fromFile() frees pochandle_index[65536] since it needs to free attached org lists
}

void loadRoutesDatabase_fromFile(char * fname)
{
	FILE * inpf;
	struct stat fileinfo;
	uint32_t * base, * ptr;
	uint32_t i, recCount[2][2], ruint, total = 0;
	size_t stringArraySize;
	struct route * node;
	uint_fast8_t best_route, status, b, s;
	uint8_t cidr;
	prefix_t * newprefix;
	patricia_node_t * pnode;
	struct routes * newroutelist;
	uint_fast16_t hash;
	struct asn_ll * asn_curr;
	unsigned int n;
	struct route_list * list;

	if (pTreeRoutes != NULL)
		return;
	inpf = fopen(fname, "rb");
	if (inpf == NULL) {
		log_printf(0, "Can't open import file %s\n", fname);
		return;
	}
	fstat(fileno(inpf), &fileinfo);
	ptr = base = mmap(NULL, fileinfo.st_size, PROT_READ, MAP_PRIVATE, fileno(inpf), 0);
	if (base == MAP_FAILED) {
		log_printf(0, "mmap() of %s failed!\n", fname);
		fclose(inpf);
		return;
	}
	posix_madvise(base, fileinfo.st_size, POSIX_MADV_SEQUENTIAL);
	stringArraySize = fileinfo.st_size - (4 + 1 + 1) * sizeof(ruint);
	for (status = 0; status <= 1; status++)
		for (best_route = 0; best_route <= 1; best_route++) {
			total += recCount[best_route][status] = num_route_records[best_route][status] = ntohl(*ptr++);
			all_route_records[best_route][status] = tst_malloc(sizeof(*node) * recCount[best_route][status]);
		}
	peersCounter = ntohl(*ptr++);
	peers = tst_malloc(sizeof(ruint) * peersCounter);
	for (i = 0; i < peersCounter; i++)
		((uint32_t *)peers)[i] = *ptr++;
	num_asn_stats = ntohl(*ptr++);
	asn_stats = tst_malloc(num_asn_stats * sizeof(struct asn_count));
	stringArraySize -= peersCounter * sizeof(ruint);
	stringArraySize -= num_asn_stats * 4 * sizeof(ruint);
	stringArraySize -= total * 8 * sizeof(ruint);
	route_strings = tst_malloc(stringArraySize);
	for (i = 0; i < num_asn_stats; i++) {
		asn_stats[i].count = ntohl(*ptr++);
		asn_stats[i].asn = ntohl(*ptr++);
		asn_stats[i].country = route_strings + ntohl(*ptr++);
		asn_stats[i].orgName = route_strings + ntohl(*ptr++);
	}
	pTreeRoutes = New_Patricia(32);
	cacheDate = time(NULL);
	inc_loading_step("ROUTES", total);
	for (status = 0; status <= 1; status++)
		for (best_route = 0; best_route <= 1; best_route++)
			for (i = 0, node = all_route_records[best_route][status]; i < recCount[best_route][status]; i++, node++) {
				node->asnPaths = route_strings + ntohl(*ptr++);
				node->createDate = ntohl(*ptr++);
				node->modifyDate = ntohl(*ptr++);
				node->routerID = ntohl(*ptr++);
				node->asn = ntohl(*ptr++);
				node->next_hop = ntohl(*ptr++);
				node->prefix = *ptr++;//
				node->cidr = cidr = ntohl(*ptr++);
				node->best_route = best_route;
				node->status = status;
				node->prefix &= htonl(~((1ULL<<(32-cidr))-1));
				newprefix = New_Prefix(AF_INET, &node->prefix, cidr);
				node->prefix = ntohl(node->prefix);//
				pnode = patricia_lookup(pTreeRoutes, newprefix);
				Deref_Prefix(newprefix);
				newroutelist = pnode->data;
				if (newroutelist == NULL) {
					newroutelist = pnode->data = tst_malloc(sizeof(*newroutelist));
					for (s = 0; s <= 1; s++)
						for (b = 0; b <= 1; b++)
							newroutelist->routes[b][s] = NULL;
				}
				list = newroutelist->routes[best_route][status];
				if (list == NULL) {
					n = 2;
					list = newroutelist->routes[best_route][status] = tst_malloc(sizeof *list + n * sizeof list->route[0]);
					list->size = n;
					n = list->num = 1;
				} else {
					n = ++list->num;
					if (n >= list->size) {
						list->size *= 2;
						list = newroutelist->routes[best_route][status] = tst_realloc(list, sizeof *list + list->size * sizeof list->route[0]);
					}
				}
				list->route[n - 1] = node;
				if (best_route != 0 && status != 0 && n > 1)
					log_printf(0, "%i\t%i.%i.%i.%i/%i\n", n, node->prefix >> 24, (node->prefix >> 16) & 0xff, (node->prefix >> 8) & 0xff, node->prefix & 0xff, node->cidr);
				hash = hash32to16(node->asn);
				asn_curr = asn_index[hash];
				while (asn_curr != NULL && asn_curr->asn != node->asn)
					asn_curr = asn_curr->next;
				if (asn_curr == NULL) {
					asn_curr = tst_malloc(sizeof(*asn_curr));
					asn_curr->next = asn_index[hash];
					asn_index[hash] = asn_curr;
					asn_curr->as = NULL;
					asn_curr->list = NULL;
                    asn_curr->transit_list = NULL;
					asn_curr->asn = node->asn;
				}
				list = asn_curr->list;
				if (list == NULL) {
					n = 16;
					list = asn_curr->list = tst_malloc(sizeof *list + n * sizeof list->route[0]);
					list->size = n;
					n = list->num = 1;
				} else {
					n = ++list->num;
					if (n >= list->size) {
						list->size *= 2;
						list = asn_curr->list = tst_realloc(list, sizeof *list + list->size * sizeof list->route[0]);
					}
				}
				list->route[n - 1] = node;
				inc_loading_step_counter();
			}
	routeCounter = recCount[1][1];
	lastTableUpdate = all_route_records[1][1]->modifyDate;
	inc_loading_step("ROUTES (STRINGS)", 1);
	memcpy(route_strings, ptr, stringArraySize);
	posix_madvise(base, fileinfo.st_size, POSIX_MADV_DONTNEED);
	munmap(base, fileinfo.st_size);
    // { TRANSIT ROUTES INDEX
    char *tok;
    char aspath_buf[384], *saveptr;
    u_int32_t transit_asn;
    inc_loading_step("ROUTES (INDEX TRANSIT)", total);
    for (status = 0; status <= 1; status++)
        for (best_route = 0; best_route <= 1; best_route++)
            for (i = 0, node = all_route_records[best_route][status] + num_route_records[best_route][status] - 1; i < num_route_records[best_route][status]; i++, node--) {
                snprintf(aspath_buf, 384, "%s", node->asnPaths);
                for (tok = strtok_r(aspath_buf, " ", &saveptr); tok; tok = strtok_r(NULL, " ", &saveptr)) {
                    transit_asn = atoi(tok);
                    if (transit_asn && transit_asn != node->asn) {
                        hash = hash32to16(transit_asn);
                        asn_curr = asn_index[hash];
                        while (asn_curr != NULL && asn_curr->asn != transit_asn)
                            asn_curr = asn_curr->next;
                        if (asn_curr != NULL) {
                            list = asn_curr->transit_list;
                            if (list == NULL) {
                                n = 16;
                                list = asn_curr->transit_list = tst_malloc(sizeof *list + n * sizeof list->route[0]);
                                list->size = n;
                                n = list->num = 1;
                            } else {
                                n = ++list->num;
                                if (n >= list->size) {
                                    list->size *= 2;
                                    list = asn_curr->transit_list = tst_realloc(list, sizeof *list + list->size * sizeof list->route[0]);
                                }
                            }
                            list->route[n - 1] = node;
                        }
                    } else {
                        break;
                    }
                }
                inc_loading_step_counter();
            }
    
    // } TRANSIT ROUTES INDEX
	fclose(inpf);
}

void DestroyRoutesData(struct routes * list)
{
	unsigned int best_route, status;

	for (status = 0; status <= 1; status++)
		for (best_route = 0; best_route <= 1; best_route++)
			if (list->routes[best_route][status] != NULL)
				tst_free(list->routes[best_route][status]);
	tst_free(list);
}

void ClearRoutesDatabase_fromFile()
{
	unsigned int i;
	uint_fast8_t best_route, status;
	struct asn_ll * asn_curr, * asn_next;
	if (pTreeRoutes == NULL)
		return;
	Destroy_Patricia(pTreeRoutes, DestroyRoutesData);
	pTreeRoutes = NULL;
	for (status = 0; status <= 1; status++)
		for (best_route = 0; best_route <= 1; best_route++) {
			tst_free(all_route_records[best_route][status]);
			all_route_records[best_route][status] = NULL;
			num_route_records[best_route][status] = 0;
		}
	tst_free(route_strings);
	route_strings = NULL;
	tst_free(peers);
	peers = NULL;
	for (i = 0; i <= 65535; i++) {
		asn_curr = asn_index[i];
		while (asn_curr != NULL) {
			if (asn_curr->list != NULL)
				tst_free(asn_curr->list);
            if (asn_curr->transit_list != NULL)
                tst_free(asn_curr->transit_list);
			asn_next = asn_curr->next;
			tst_free(asn_curr);
			asn_curr = asn_next;
		}
		asn_index[i] = NULL;
	}
	tst_free(asn_stats);
	asn_stats = NULL;
	num_asn_stats = 0;
}

void loadACL_fromFile(char * fname)
{
	uint32_t recCount, i, ip, cidr, max_count, status;
	int isnew;
	struct ip * newip;
	char thisRoute[50], host[20];
	FILE * inpf;

	if (requests == NULL)
		requests = New_Patricia(32);
	inpf = fopen(fname, "rb");
	if (inpf == NULL) {
		log_printf(0, "Can't open import file %s\n", fname);
		return;
	}
	fread(&recCount, sizeof(recCount), 1, inpf);
	recCount = ntohl(recCount);
	for (i = 0; i < recCount; i++) {
		fread(&ip, sizeof(ip), 1, inpf);
		ip = ntohl(ip);
		fread(&cidr, sizeof(cidr), 1, inpf);
		cidr = ntohl(cidr);
		fread(&max_count, sizeof(max_count), 1, inpf);
		max_count = ntohl(max_count);
		fread(&status, sizeof(status), 1, inpf);
		status = ntohl(status);
		sprintf(thisRoute, "%s", ipv4_decimal_to_quaddot(ip, host, 20));
		newip = get_acl_for_ip(&isnew, thisRoute, cidr);
		decimal_to_bytes(ip, newip->ip);
		newip->count = 0;
		if (isnew) {
			newip->lastQuery = 0;
			newip->lastReset = 0;
			newip->firstQuery = 0;
		}
		newip->limit = max_count;
		newip->acl = status;
	}
	log_printf(0, "ACL loaded\n");
}

void ACL_Reload_fromFile(int stub)
{
	(void)stub;
	loadACL_fromFile(ACLDB_EXPORT_FILENAME);
}

/*----------------------------------------- Fast load -----------------------------------------*/

static unsigned char empty_peer_ip[]={0,0,0,0};
void getPeerIP(uint32_t idx, char * buf)
{
    unsigned char * p=empty_peer_ip;
    if(idx<peersCounter)
        p=(unsigned char *)(peers+idx*4);
    sprintf(buf,"%u.%u.%u.%u",(unsigned int)(p[0]),(unsigned int)(p[1]),(unsigned int)(p[2]),(unsigned int)(p[3]));
}

struct ip * get_acl_for_ip(int * isnew, char * ipstr, unsigned int cidr)
{
    patricia_node_t * trieNode;
    struct ip * newip;
    char thisRoute[50];
    uint32_t ulip;

	sprintf(thisRoute, "%s/%d", ipstr, cidr);
    ipv4_quaddot_to_decimal(ipstr, &ulip);

	trieNode = try_search_best(requests, thisRoute);
    if(trieNode == NULL)
    {
        *isnew=1;
		newip = (struct ip *)tst_malloc(sizeof(struct ip));
        decimal_to_bytes(ulip, newip->ip);
		newip->cidr=cidr;
		newip->count=0;
		newip->lastQuery=0;
		newip->lastReset=0;
		newip->firstQuery=0;
        //we don't know here how to initialize these fields.
        //Our responsibility here is only to allocate memory and insert in patricia
		newip->acl=0;
		newip->limit=0;
        trieNode=make_and_lookup(requests,thisRoute);
		trieNode->data=(void *)newip;
    } else {
		*isnew = 0;
        newip=(struct ip *)trieNode->data;
	}
    return newip;
}

int handleWhoisRequest(char * ipcidr,
					   char * network, 
					   uint32_t * asn,
					   char * asnPaths,
					   time_t * tcrdt,
					   time_t * tmddt,
					   uint32_t * next_hop,
					   char * as_orgName,
					   uint32_t * as_orgNameSrc,
					   char * orgName,
					   uint32_t * orgNameSrc,
					   char * netName,
					   uint32_t * netNameSrc,
					   p_geo_iprange * geo,
					   struct org_list ** orglist,
					   unsigned int * opos,
					   struct netblock ** netblk,
					   struct asn ** as)
{
	char ip[50],c_cidr[10];
	int cidr;
	uint32_t ulip;
	patricia_node_t * node;
	struct route * fndroute;
	struct routes * rlist;
	uint_fast16_t hash;
	struct asn_ll * asn_curr;
	struct org_list * olist;
	unsigned int r;
	struct netblock * net;

	log_printf(4, "handleWhoisRequest checkpoint 1\n");
	ipv4_parse(ipcidr,ip,c_cidr);
	log_printf(4, "handleWhoisRequest checkpoint 2\n");
	if(!c_cidr[0])
	{
		c_cidr[0]='3';
		c_cidr[1]='2';
		c_cidr[2]=0;
		cidr=32;
	}
	else
		cidr=strtoul(c_cidr,NULL,10);
	if(cidr<0 || cidr>32)
	{
		c_cidr[0]='3';
		c_cidr[1]='2';
		c_cidr[2]=0;
		cidr=32;
	}
	ipv4_quaddot_to_decimal(ip, &ulip);
	
	log_printf(4, "handleWhoisRequest checkpoint 3\n");
	node=try_search_best(pTreeRoutes, ipcidr);
	log_printf(4, "handleWhoisRequest checkpoint 4\n");
	while (node != NULL) {
		rlist = node->data;
		if (node->prefix != NULL && rlist != NULL && rlist->routes[1][1] != NULL) {
			sprintf(network, "%s/%d", prefix_toa(node->prefix), node->prefix->bitlen);
			if (rlist->routes[1][1]->num > 1)
				log_printf(2, "handleWhoisRequest: #best = %i\n", rlist->routes[1][1]->num);
			fndroute = rlist->routes[1][1]->route[0];
			strcpy(asnPaths, fndroute->asnPaths);
			*asn = fndroute->asn;
			*tcrdt = fndroute->createDate;
			*tmddt = fndroute->modifyDate;
			*next_hop = fndroute->next_hop;
			hash = hash32to16(fndroute->asn);
			asn_curr = asn_index[hash];
			while (asn_curr != NULL && (asn_curr->as == NULL || asn_curr->asn != fndroute->asn))
				asn_curr = asn_curr->next;
			as_orgName[0] = '\0';
			*as_orgNameSrc = 0;
			*orglist = NULL;
			*as = NULL;
			if (asn_curr != NULL) {
			*as = asn_curr->as;
				hash = hashstringto16(asn_curr->as->org_id, CASE_INSENSITIVE);
				olist = orgid_index_org[hash];
				r = 0;
				if (olist != NULL) {
					while (r < olist->num && strcasecmp(asn_curr->as->org_id, olist->org[r]->org_id) != 0)
						r++;
					if (r < olist->num)
						*orglist = olist;
					*opos = r;
				}
				if (asn_curr->as->asOrgName[0] != '\0') {
					strcpy(as_orgName, asn_curr->as->asOrgName);
					*as_orgNameSrc = asn_curr->as->source;
				} else
					if (olist != NULL && r < olist->num) {
						strcpy(as_orgName, olist->org[r]->orgName);
						*as_orgNameSrc = olist->org[r]->source;
					}
			}
			netName[0] = '\0';
			orgName[0] = '\0';
			*netblk = NULL;
			node = try_search_best(pTreeNet, ipcidr);
			while (node != NULL) {
				net = node->data;
				if (net != NULL && net->status >= 1)
					break;
				node = node->parent;
			}
			if (node != NULL) {
				*netblk = net = node->data;
				strcpy(netName, net->netName);
				*netNameSrc = net->source;
				if (net->orgName[0] == '\0') {
					hash = hashstringto16(net->org_id, CASE_INSENSITIVE);
					olist = orgid_index_org[hash];
					r = 0;
					if (olist != NULL) {
						while (r < olist->num && strcasecmp(net->org_id, olist->org[r]->org_id) != 0)
							r++;
						if (r < olist->num) {
							*orglist = olist;
							*opos = r;
							strcpy(orgName, olist->org[r]->orgName);
							*orgNameSrc = olist->org[r]->source;
						}
					}
				} else {
					strcpy(orgName, net->orgName);
					*orgNameSrc = net->source;
				}
			}
			if(cidr==32) {
				log_printf(4, "handleWhoisRequest checkpoint 5\n");
				ipv4_quaddot_to_decimal(ip, &ulip);
				*geo=FindIPRange(ulip);
			} else {
				log_printf(4, "handleWhoisRequest checkpoint 6\n");
				*geo=NULL;
			}
			return 1;
		}
		node = node->parent;
		log_printf(4, "handleWhoisRequest: going to parent\n");
	}
	return 0;
}

void getVersionRuntime(char * response, int sz)
{
    char tmp[1024], *p=tmp;
    char tmptm[100];
    p[0]=0;
	
    sprintf(p,"%s (%s) %s\n",PROGNAME,VERSION,COPYRIGHT);p+=strlen(p);
    GetDateTimeFormat(lastTableUpdate, tmptm, 99);
	sprintf(p,"Global BGP routing table cache last updated %s\n",tmptm);p+=strlen(p);
	sprintf(p,"Cache contains %d global prefixes from %d peers\n",routeCounter,peersCounter);p+=strlen(p);
    GetDateTimeFormat(pwhoisdStart, tmptm, 99);
	sprintf(p,"Server responded to %lu requests from %lu unique IPs since %s\n",
			getCounter(CNTR_QUERY_PWHOIS),getCounter(CNTR_UNIQUE_PEERS),tmptm);
    strncpy(response,tmp,sz);
}

//functions for traversal through requests radix tree
static size_t internal_process_all_requests(int * error, patricia_node_t *node, process_ip func, void * cookie)
{
    size_t n = 0;
    if(!func || error[0])
        return 0;
    if(node->l)
    {
        n+=internal_process_all_requests(error, node->l, func, cookie);
        if(error[0])
            return n;
    }
    if(node->prefix && node->data)
    {
	    error[0]=func((struct ip *)(node->data),cookie);
	    n++;
        if(error[0])
            return n;
    }
    if(node->r)
		n+=internal_process_all_requests(error, node->r, func, cookie);
    return n;
}

size_t process_all_requests(int * error, process_ip func, void * cookie)
{
    *error=0;
    return internal_process_all_requests(error, requests->head, func, cookie);
}

static size_t my_read(pwhois_thread_cb * cb, char * ptr)
{
	if(cb->rl_cnt<=0)
	{
again:
		if((cb->rl_cnt=read(cb->sock, cb->rl_buf, MAX_BUFFER_LEN))<0)
		{
			if(errno==EINTR)
				goto again;
			return -1;
		}
		else
			if(cb->rl_cnt==0)
				return 0;
		cb->rl_bufptr=cb->rl_buf;
	}
	cb->rl_cnt--;
	*ptr=*cb->rl_bufptr++;
	return 1;
}

static size_t readline(pwhois_thread_cb * cb, char * ptr, size_t maxlen)
{
	size_t n, rc;
	char c;
	for(n=0;n<maxlen;n++)
	{
		if((rc=my_read(cb,&c))==1)
		{
			*ptr = c;
			if(c=='\n' || c=='\r')
				break;
			ptr++;
		}
		else
		{
			if(rc==0)
			{
				*ptr=0;
				return n;
			}
			else
				return -1;
		}
	}
	*ptr=0;
	return n;
}

static void registerClient(int sock, pwhois_thread_cb * cb)
{
    struct sockaddr_in name, localname;
    int namelen;
    int isnew;
    struct timeval timeout;
#ifdef SO_LINGER
    struct linger lingval;
#endif

    timeout.tv_sec=15;
    timeout.tv_usec=0;
    setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    timeout.tv_sec=10;
    timeout.tv_usec=0;
    setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
#ifdef SO_LINGER
    lingval.l_onoff=1;
    lingval.l_linger=10;	/* lock in close and wait 10 seconds to send remainder of data before closing */
    setsockopt(sock,SOL_SOCKET,SO_LINGER,&lingval,sizeof(lingval));
#endif

    bzero((char*)&name,sizeof(name));
    bzero((char*)&localname,sizeof(name));
	namelen=sizeof(name);
	getpeername(sock,(struct sockaddr *)&name,(socklen_t*)&namelen);
	namelen=sizeof(localname);
	getsockname(sock,(struct sockaddr *)&localname,(socklen_t*)&namelen);
	
	/* thread safe versions */
	//addr2ascii(AF_INET, &name.sin_addr, sizeof(name.sin_addr), cb->peerIp);	
	if(own_inet_ntoa_r(name.sin_addr, cb->peerIp, 255) == NULL) {
		log_printf(0, "Error: unable to translate IP: %ul\n", name.sin_addr);
	}

	//addr2ascii(AF_INET, &name.sin_addr, sizeof(localname.sin_addr), cb->localIp);	
	if(own_inet_ntoa_r(localname.sin_addr, cb->localIp, 255) == NULL) {
		log_printf(0, "Error: unable to translate IP: %ul\n", localname.sin_addr);
	}

	cb->localPort=ntohs(localname.sin_port);
	//find ACL record here
    cb->currentACL=get_acl_for_ip(&isnew, cb->peerIp, 32);
	/* It's extra checking - get_acl_for_ip will create new acl record if there is no such one for this ip */
	
    cb->lastRegTime=CurrentTime();
    if(isnew)
    {
        cb->currentACL->acl=1;
        cb->currentACL->count=0;
        cb->currentACL->limit=getQueriesLimit();
		cb->currentACL->lastQuery=cb->lastRegTime;
		cb->currentACL->lastReset=cb->lastRegTime;
        cb->currentACL->firstQuery=cb->lastRegTime;
		incCounter(CNTR_UNIQUE_PEERS);
    }
    else
    {
		if(!cb->currentACL->acl)
		{
			if (!cb->currentACL->firstQuery)
			{
				cb->currentACL->lastReset=cb->lastRegTime;
				cb->currentACL->firstQuery=cb->lastRegTime;
				incCounter(CNTR_UNIQUE_PEERS);
			}
			cb->currentACL->count++;
			cb->currentACL->lastQuery=cb->lastRegTime;
		}
		else
		{
			if(!cb->currentACL->firstQuery)
			{
				cb->currentACL->lastQuery=cb->lastRegTime;
				cb->currentACL->lastReset=cb->lastRegTime;
				cb->currentACL->firstQuery=cb->lastRegTime;
				incCounter(CNTR_UNIQUE_PEERS);
			}
			else
			{
				if(cb->currentACL->limit && cb->lastRegTime - cb->currentACL->lastReset >= 24 * 3600)
				{
					cb->currentACL->count=0;
					cb->currentACL->lastReset=cb->lastRegTime;
				}
			}
		}
    }
	cb->busy=1;
	incCounter(CNTR_ACTIVE_CONN);
	cb->bulk=0;
	cb->bulkCount=0;
	cb->application[0]='\0';
	cb->displayType=PW_PWHOIS;
	cb->dataType=PW_DATA_NORMAL;
	cb->sock=sock;
	cb->rl_cnt=0;
}

void trim_line(char * line)
{
	int i;
	for(i=strlen(line)-1;i>=0;i--)
	{
		if(line[i]=='\n' || line[i]=='\r')
			line[i]=0;
	}
}

void report_rotate()
{
	time_t now;
	struct tm tm;
	char reportfilename[1024];
	ssize_t slen;

	if (reportpath[0] == '\0')
		return;
	pthread_mutex_lock(&reportfilelock);
	if (reportfile != NULL) {
		fflush(reportfile);
		fclose(reportfile);
		reportfile = NULL;
	}
	time(&now);
	gmtime_r(&now, &tm);
	slen = snprintf(reportfilename, 1024, "%s/", reportpath);
	if (slen >= 1024 || slen < 0)
		goto report_rotate_unlock;
	if (strftime(reportfilename + slen, 1024 - slen, "%F_%T.csv", &tm) == 0)
		goto report_rotate_unlock;
	reportfile = fopen(reportfilename, "w");
	if (reportfile == NULL)
		log_printf(0, "Error creating report file\n");
	else
		fprintf(reportfile, "Year-Mo-Dy_Hr:Mn:Sc,serverIP,srcIP,ACL,count,limit,threadnum,threadreqcount,threadbulkcount,query,app\n");
report_rotate_unlock:
	pthread_mutex_unlock(&reportfilelock);
}

void report_write(pwhois_thread_cb * cb, char * query)
{
	time_t now;
	struct tm tm;
	char line[4096];
	ssize_t slen;
	ssize_t retval;

	pthread_mutex_lock(&reportfilelock);
	if (reportfile == NULL) {
		goto report_write_unlock;
	}
	time(&now);
	gmtime_r(&now, &tm);
	if (strftime(line, 4096, "%F_%T,", &tm) == 0)
		goto report_write_unlock;
	slen = strlen(line);
	retval = snprintf(line + slen, 4096 - slen, "%s,%s,%i,%i,%i,%li,%li,%i,%s,%s\n", cb->localIp, cb->peerIp, cb->currentACL->acl, cb->currentACL->count, cb->currentACL->limit, cb - threads_pool, cb->reqcount, cb->bulkCount, query, cb->application);
	if (retval < 0 || retval > (4096 - slen))
		goto report_write_unlock;
	fwrite(line, slen + retval, 1, reportfile);
	fflush(reportfile);
report_write_unlock:
	pthread_mutex_unlock(&reportfilelock);
}

void * databaseReloadThread(void * stub)
{
	(void)stub;
	checkDBReferenceAndLock();
	//now DatabaseIsLoaded=0
	if(pthread_mutex_trylock(&reloadlock) == EBUSY) //already executes databaseReloadThread
		return NULL;
	report_rotate();
	LOADING_STEP=0;
	LOADING_STEP_NAME=NULL;
	LOADING_STEP_SIZE=0;
	LOADING_STEP_CURR=0;
	log_printf(0, "Clear ASN data....\n");
	ClearASNDatabase_fromFile();
	log_printf(0, "Clear routing data....\n");
	ClearRoutesDatabase_fromFile();
	log_printf(0, "Clear GEO data....\n");
	CleanGeoData_fromFile();
	log_printf(0, "Clear Net data....\n");
	ClearNetDatabase_fromFile();
	log_printf(0, "Clear POC data....\n");
	ClearPOCDatabase_fromFile();
	log_printf(0, "Clear Org data....\n");
	ClearOrgDatabase_fromFile();
	//now we can handle extra queries but we need load routes database to handle standard queries
	log_printf(0, "Loading ASN data....\n");
	loadASNDatabase_fromFile(ASNDB_EXPORT_FILENAME);	// ASN must load before Routes
	log_printf(0, "Loading routing data....\n");
	loadRoutesDatabase_fromFile(ROUDB_EXPORT_FILENAME);
	log_printf(0, "Loading GEO data....\n");
	LoadGeoData_fromFile(GEODB_EXPORT_FILENAME);
	log_printf(0, "Loading Net data....\n");
	loadNetDatabase_fromFile(NETDB_EXPORT_FILENAME);
	log_printf(0, "Loading POC data....\n");
	loadPOCDatabase_fromFile(POCDB_EXPORT_FILENAME);	// POC must load before Org
	log_printf(0, "Loading Org data....\n");
	loadOrgDatabase_fromFile(ORGDB_EXPORT_FILENAME);
	log_printf(0, "All are loaded....\n");
	DatabaseIsLoaded = 1;
	pthread_mutex_unlock(&reloadlock);
	return NULL;
}

static pthread_t dbreloadthread_id;
void databaseReload(int stub)
{
	(void)stub;
	log_printf(0, "Reloading signal is received....\n");
	pthread_create(&dbreloadthread_id,NULL,databaseReloadThread,NULL);
	log_printf(0, "Reloading thread is started....\n");
}

void * pwhois_thread(void * ctrBlock)
{
	int connfd,rlen;
	socklen_t clilen;
	struct sockaddr cliaddr;
	pwhois_thread_cb * cb=(pwhois_thread_cb *)ctrBlock;
	char request[MAX_BUFFER_LEN];
	
	log_printf(0, "Thread %d starting ....\n",cb-threads_pool);
	while(1)
	{
		clilen=addrLength;
		pthread_mutex_lock(&mutexlock);
		connfd=accept(listen_sock,&cliaddr,&clilen);
		pthread_mutex_unlock(&mutexlock);
		if (connfd < 0)
			continue;
		registerClient(connfd, cb);
		//handle requests
		while((rlen=readline(cb, request, MAX_BUFFER_LEN))>=0)
		{
			if(!rlen)
			{
				rlen=readline(cb, request, MAX_BUFFER_LEN);
				if(rlen<=0)
					break;
			}
			trim_line(request);
			// break out if error, not a bulk command or not an attribute command
			if(parse_and_execute(request, cb) < 0 || (!cb->bulk && !cb->attribute))
				break;
		}
		if(shutdown(connfd, SHUT_WR)==0)
			while(read(connfd,request,MAX_BUFFER_LEN)>0);
		close(connfd);
		cb->busy=0;
		decCounter(CNTR_ACTIVE_CONN);
	}
	return NULL;
}

pwhois_thread_cb * initialize_threads(int listenfd, int addrlen, int count)
{
	int i;
	listen_sock=listenfd;
	threads_pool=tst_calloc(sizeof(pwhois_thread_cb),count);
	addrLength=addrlen;
	pool_length=count;
	pwhoisdStart = time(NULL);
	initialize_all_counters();
	for (i = 0; i <= 65535; i++) {
		asn_index[i] = NULL;
		orgid_index_net[i] = NULL;
		orgid_index_org[i] = NULL;
		pochandle_index[i] = NULL;
	}
	for(i=0;i<count;i++)
	{
		threads_pool[i].busy=0;
		threads_pool[i].reqcount=0;
		pthread_create(&threads_pool[i].tid,NULL,pwhois_thread,(void *)&threads_pool[i]);
	}
	return threads_pool;
}

int parse_req(char *pattern, const char *req, regmatch_t *args, int nargs)
{
	int status; 
	regex_t re; 
	size_t s;
	
	(!args) ? (s=0) : (s=nargs); 
	if(regcomp(&re, pattern, REG_EXTENDED|REG_ICASE) != 0)
		return 0; 
	status = regexec(&re, req, s, args, 0); 
	regfree(&re); 
	return !status; 
}

static char NETTP_UNKNOWN[]       ="unknown";
static char NETTP_ASSIGNMENT[]    ="assignment";
static char NETTP_REASSIGNMENT[]  ="reassignment";
static char NETTP_RIR[]           ="rir";
static char NETTP_ALLOCATION[]    ="allocation";

static char * NETTP[] = {NETTP_UNKNOWN, NETTP_ASSIGNMENT, NETTP_REASSIGNMENT, NETTP_RIR, NETTP_ALLOCATION};

char * getNetType(int netType)
{
	if (netType < 0 || netType > 4)
		netType = 0;
	return NETTP[netType];
}

int sendNetblockLine(pwhois_thread_cb * cb, struct netblock * net, char * response)
{
	char crdt[25], mddt[25], netRange[40];

	GetDateTimeFormat(net->createDate, crdt, 25);
	GetDateTimeFormat(net->modifyDate, mddt, 25);
	ipv4_decimal_to_quaddot(net->network, netRange, 20);
	sprintf(netRange + strlen(netRange), " - ");
	ipv4_decimal_to_quaddot(net->enetrange, netRange + strlen(netRange), 20);
	sprintf(response,"*> %39s | %20s | %14s | %13s | %11s | %24s | %24s\n", netRange, net->netName, getNetType(net->netType), net->registerDate, net->updateDate, crdt, mddt);
	if (writestr(cb, response))
		return -1;
	return 0;
}

int getNetblockBySourceAS(pwhois_thread_cb * cb, uint32_t srcas)
{
	char response[512];
	uint_fast16_t hash;
	struct asn_ll * asn_curr;
	struct org_list * orglist;
	struct net_list * netlist;
	struct org * org;
	struct netblock * net;
	unsigned int i, n, r;

	incCounter(CNTR_QUERY_NBLCK_AS);
	hash = hash32to16(srcas);
	asn_curr = asn_index[hash];
	while (asn_curr != NULL && asn_curr->asn != srcas)
		asn_curr = asn_curr->next;
	org = NULL;
	if (asn_curr == NULL || asn_curr->as == NULL)
		netlist = NULL;
	else {
		hash = hashstringto16(asn_curr->as->org_id, CASE_INSENSITIVE);
		netlist = orgid_index_net[hash];
		orglist = orgid_index_org[hash];
		if (orglist != NULL) {
			for (r = 0; r < orglist->num && strcasecmp(asn_curr->as->org_id, orglist->org[r]->org_id) != 0; r++)
				continue;
			if (r < orglist->num)
				org = orglist->org[r];
		}
	}
	i = 0;
	if (netlist != NULL)
		for (n = 0; n < netlist->num; n++) {
			net = netlist->net[n];
			if (strcasecmp(asn_curr->as->org_id, net->org_id) != 0)
				continue;
			if (i == 0) {
				sprintf(response, "Origin-AS: %"PRIu32"\nOrg-ID: %s\nOrg-Name: %s\n"
						"    Net-Range                              | Net-Name             | Net-Type       | Register-Date | Update-Date | Create-Date              | Modify-Date              \n", srcas, org == NULL ? net->org_id : org->orgName, org == NULL ? net->orgName : org->orgName);
				if (writestr(cb, response))
					return -1;
			}
			if (sendNetblockLine(cb, net, response))
				return -1;
			i++;
		}
	if (i == 0) {
		sprintf(response, "No netblocks found in registry database for source-as=%"PRIu32"\n", srcas);
		if (writestr(cb, response))
			return -1;
	}
	return 0;
}

int getNetblockByOrgId(pwhois_thread_cb * cb, char * orgid)
{
	char response[512];
	uint_fast16_t hash;
	struct org_list * orglist;
	struct net_list * netlist;
	struct org * org;
	struct netblock * net;
	unsigned int n, r, output;

	incCounter(CNTR_QUERY_NBLCK_OI);
	hash = hashstringto16(orgid, CASE_INSENSITIVE);
	orglist = orgid_index_org[hash];
	org = NULL;
	if (orglist != NULL) {
		for (r = 0; r < orglist->num && strcasecmp(orgid, orglist->org[r]->org_id) != 0; r++)
			continue;
		if (r < orglist->num)
			org = orglist->org[r];;
	}
	netlist = orgid_index_net[hash];
	output = 0;
	if (netlist != NULL)
		for (n = 0; n < netlist->num; n++) {
			if (strcasecmp(orgid, netlist->net[n]->org_id) != 0)
				continue;
			net = netlist->net[n];
			if (output == 0) {
				sprintf(response,"Org-ID: %s\nOrg-Name: %s\n"
						"    Net-Range                              | Net-Name             | Net-Type       | Register-Date | Update-Date | Create-Date              | Modify-Date              \n",
						org == NULL ? net->org_id : org->org_id, org == NULL ? net->orgName : org->orgName);
				if (writestr(cb, response))
					return -1;
			}
			if (sendNetblockLine(cb, net, response))
				return -1;
			output++;
		}
	if (output == 0) {
		sprintf(response, "No netblocks found in registry database for org-id=%s\n", orgid);
		if (writestr(cb, response))
			return -1;
	}
	return 0;
}

void prepareRegistryRecord(char * response, int record_num, struct org * org, int type)
{
	char crdt[25], mddt[25], * presponse;
	time_t tcrdt, tmddt;
	int s;

	presponse = response;
	sprintf(presponse, "Org-Record: %i\n", record_num);
	presponse += strlen(presponse);
	sprintf(presponse, "Org-ID: %s\n", org->org_id);
	presponse += strlen(presponse);
	sprintf(presponse, "Org-Name: %s\n", org->orgName);
	presponse += strlen(presponse);
	sprintf(presponse, "Can-Allocate: %i\n", org->canAllocate);
	presponse += strlen(presponse);
	for (s = 0; s < 6; s++)
		if (org->street[s][0] != '\0') {
			sprintf(presponse, "Street-%i: %s\n", s + 1, org->street[s]);
			presponse += strlen(presponse);
		}
	if (org->city[0] != '\0') {
		sprintf(presponse, "City: %s\n", org->city);
		presponse += strlen(presponse);
	}
	if (org->state[0] != '\0') {
		sprintf(presponse, "State: %s\n", org->state);
		presponse += strlen(presponse);
	}
	if (org->postalCode[0] != '\0') {
		sprintf(presponse, "Postal-Code: %s\n", org->postalCode);
		presponse += strlen(presponse);
	}
	if (org->country[0] != '\0') {
		sprintf(presponse, "Country: %s\n", org->country);
		presponse += strlen(presponse);
	}
	if (org->registerDate[0] != '\0') {
		sprintf(presponse, "Register-Date: %s\n", org->registerDate);
		presponse += strlen(presponse);
	}
	if (org->updateDate[0] != '\0') {
		sprintf(presponse, "Update-Date: %s\n", org->updateDate);
		presponse += strlen(presponse);
	}
	tcrdt = org->createDate;
	if (tcrdt != 0) {
		GetDateTimeFormat(tcrdt, crdt, 25);
		sprintf(presponse, "Create-Date: %s\n", crdt);
		presponse += strlen(presponse);
	}
	tmddt = org->modifyDate;
	if (tmddt != 0) {
		GetDateTimeFormat(tmddt, mddt, 25);
		sprintf(presponse, "Modify-Date: %s\n", mddt);
		presponse += strlen(presponse);
	}
	presponse += _getRegistryByPOCHandleShort(presponse, org->adminHandle, "Admin", type);
	presponse += _getRegistryByPOCHandleShort(presponse, org->nocHandle, "NOC", type);
	presponse += _getRegistryByPOCHandleShort(presponse, org->abuseHandle, "Abuse", type);
	presponse += _getRegistryByPOCHandleShort(presponse, org->techHandle, "Tech", type);
	if (org->referralServer[0] != '\0') {
		sprintf(presponse, "Referral-Server: %s\n", org->referralServer);
		presponse += strlen(presponse);
	}
	if (org->comment[0] != '\0') {
		sprintf(presponse, "Comment: %s\n", org->comment);
		presponse += strlen(presponse);
	}
}

int sendRegistryRecord(pwhois_thread_cb * cb, int record_num, struct org * org, int type, char * response)
{
	prepareRegistryRecord(response, record_num, org, type);
	if (writestr(cb, response))
		return -1;
	return 0;
}

int getRegistryByEmail(pwhois_thread_cb * cb, char * mailbox_suffix, int type)
{
	char crdt[25], mddt[25], response[4096], * presponse;
	time_t tcrdt, tmddt;
	struct poc * node;
	struct org_list * orglist;
	unsigned int i, j, s, slen, mlen, output;
	char ch;

	incCounter(CNTR_QUERY_REGTR_EM);
	slen = strlen(mailbox_suffix);
	for (i = 0; i < (unsigned int)slen; i++)
		if (mailbox_suffix[i] >= 'A' && mailbox_suffix[i] <= 'Z')
			mailbox_suffix[i] |= ATOLOWER;
	output = 0;
	for (i = 0, node = all_poc_records; i < num_poc_records; i++, node++) {
		mlen = strlen(node->mailbox);
		if (mlen < slen)
			continue;
		for (j = 1; j <= slen; j++) {
			ch = node->mailbox[mlen-j];
			if (ch >= 'A' && ch <= 'Z')
				ch |= ATOLOWER;
			if (ch != mailbox_suffix[slen-j])
				break;
		}
		if (j <= slen)
			continue;
		presponse = response;
		sprintf(presponse, "POC-Record: %i\n", output);
		presponse += strlen(presponse);
		sprintf(presponse, "POC-Handle: %s\n", node->pocHandle);
		presponse += strlen(presponse);
		sprintf(presponse, "Is-Role: %i\n", node->isrole);
		presponse += strlen(presponse);
		if (node->isrole) {
			if (node->roleName[0] != '\0') {
				sprintf(presponse, "Role-Name: %s\n", node->roleName);
				presponse += strlen(presponse);
			}
		} else {
			if (node->firstName[0] != '\0') {
				sprintf(presponse, "First-Name: %s\n", node->firstName);
				presponse += strlen(presponse);
			}
			if (node->middleName[0] != '\0') {
				sprintf(presponse, "Middle-Name: %s\n", node->middleName);
				presponse += strlen(presponse);
			}
			if (node->lastName[0] != '\0') {
				sprintf(presponse, "Last-Name: %s\n", node->lastName);
				presponse += strlen(presponse);
			}
		}
		for (s = 0; s < 6; s++)
			if (node->street[s][0] != '\0') {
				sprintf(presponse, "Street-%i: %s\n", s + 1, node->street[s]);
				presponse += strlen(presponse);
			}
		if (node->city[0] != '\0') {
			sprintf(presponse, "City: %s\n", node->city);
			presponse += strlen(presponse);
		}
		if (node->state[0] != '\0') {
			sprintf(presponse, "State: %s\n", node->state);
			presponse += strlen(presponse);
		}
		if (node->postalCode[0] != '\0') {
			sprintf(presponse, "Postal-Code: %s\n", node->postalCode);
			presponse += strlen(presponse);
		}
		if (node->country[0] != '\0') {
			sprintf(presponse, "Country: %s\n", node->country);
			presponse += strlen(presponse);
		}
		if (node->registerDate[0] != '\0') {
			sprintf(presponse, "Register-Date: %s\n", node->registerDate);
			presponse += strlen(presponse);
		}
		if (node->updateDate[0] != '\0') {
			sprintf(presponse, "Update-Date: %s\n", node->updateDate);
			presponse += strlen(presponse);
		}
		tcrdt = node->createDate;
		if (tcrdt != 0) {
			GetDateTimeFormat(tcrdt, crdt, 25);
			sprintf(presponse, "Create-Date: %s\n", crdt);
			presponse += strlen(presponse);
		}
		tmddt = node->modifyDate;
		if (tmddt != 0) {
			GetDateTimeFormat(tmddt, mddt, 25);
			sprintf(presponse, "Modify-Date: %s\n", mddt);
			presponse += strlen(presponse);
		}
		if (node->comment[0] != '\0') {
			sprintf(presponse, "Comment: %s\n", node->comment);
			presponse += strlen(presponse);
		}
		if (node->officePhone[0]!= '\0') {
			sprintf(presponse, "Office-Phone: %s\n", node->officePhone);
			presponse += strlen(presponse);
		}
		sprintf(presponse, "Mailbox: %s\n", node->mailbox);
		presponse += strlen(presponse);
		if (writestr(cb, response))
			return -1;
		if (type)
			for (j = 0, orglist = node->poc->orglist; orglist != NULL && j < orglist->num; j++)
				if (sendRegistryRecord(cb, j, orglist->org[j], 0, response))
					return -1;
		output++;
	}
	if (output == 0) {
		sprintf(response, "No point of contact found in registry database for email=%s\n", mailbox_suffix);
		if (writestr(cb, response))
			return -1;
	}
	return 0;
}

int getRegistryByOrgId(pwhois_thread_cb * cb, char * orgid, int type)
{
	char response[4096];
	int i;
	uint_fast16_t hash;
	struct org_list * list;
	unsigned int r;

	incCounter(CNTR_QUERY_REGTR_OI);
	hash = hashstringto16(orgid, CASE_INSENSITIVE);
	list = orgid_index_org[hash];
	i = 0;
	if (list != NULL)
		for (r = 0; r < list->num; r++) {
			if (strcasecmp(orgid, list->org[r]->org_id) != 0)
				continue;
			if (sendRegistryRecord(cb, i, list->org[r], type, response))
				return -1;
			i++;
		}
	if (i == 0) {
		sprintf(response, "No organization found in registry database for org-id=%s\n", orgid);
		if (writestr(cb, response))
			return -1;
	}
	return 0;
}

void bm_bad_char(int * bad_char, uint8_t * pattern, int patlen)
{
	int i;
	for (i = 0; i < 256; i++)
		bad_char[i] = patlen;
	for (i = 0; i < patlen; i++)
		bad_char[pattern[i]] = patlen - 1 - i;
}

int bm_suffix_is_prefix(uint8_t * pattern, int patlen, int pos)
{
	int i;
	int slen = patlen - pos;
	for (i = 0; i < slen; i++)
		if (pattern[i] != pattern[pos+i])
			return 0;
	return 1;
}

int bm_longest_suffix_length(uint8_t * pattern, int patlen, int pos)
{
	int i;
	for (i = 0; (pattern[pos-i] == pattern[patlen-1-i]) && (i < pos); i++)
		continue;
    return i;
}

void bm_good_suffix(int * good_suffix, uint8_t * pattern, int patlen)
{
	int p, slen;
	int last_prefix_index = patlen - 1;

	for (p = patlen - 1; p >= 0; p--) {
		if (bm_suffix_is_prefix(pattern, patlen, p + 1))
			last_prefix_index = p + 1;
		good_suffix[p] = last_prefix_index + patlen - 1 - p;
	}
	for (p = 0; p < patlen - 1; p++) {
		slen = bm_longest_suffix_length(pattern, patlen, p);
		if (pattern[p-slen] != pattern[patlen-1-slen])
			good_suffix[patlen-1-slen] = patlen - 1 - p + slen;
	}
}

#define max(a,b) ((a)>(b)?(a):(b))

uint8_t * bm_search(uint8_t * string, uint8_t * pattern)
{
	int i, j;
	int slen = strlen((char *)string);
	int plen = strlen((char *)pattern);
	int bad_char[256];
	int * good_suffix = tst_malloc(plen * sizeof(i));
	bm_bad_char(bad_char, pattern, plen);
	bm_good_suffix(good_suffix, pattern, plen);
	i = plen - 1;
	while (i < slen) {
		j = plen - 1;
		while (j >= 0 && string[i] == pattern[j]) {
			i--;
			j--;
		}
		if (j < 0) {
			tst_free(good_suffix);
			return string + i + 1;
		}
		i += max(bad_char[string[i]], good_suffix[j]);
	}
	tst_free(good_suffix);
	return NULL;
}

int getRegistryByOrgName(pwhois_thread_cb * cb, char * orgname, int type)
{
	char response[4096];
	unsigned int i;
	int k, n, output, klen, nlen;
	int bad_char[256];
	int * good_suffix;
	struct org * node;
	char ch;

	incCounter(CNTR_QUERY_REGTR_ON);
	klen = strlen(orgname);
	for (i = 0; i < (unsigned int)klen; i++)
		if (orgname[i] >= 'a' && orgname[i] <= 'z')
			orgname[i] &= ATOUPPER;
	good_suffix = tst_malloc(klen * sizeof(i));
	bm_bad_char(bad_char, (uint8_t *)orgname, klen);
	bm_good_suffix(good_suffix, (uint8_t *)orgname, klen);
	output = 0;
	for (i = 0, node = all_org_records; i < num_org_records; i++, node++) {
		nlen = strlen(node->orgName);
		n = klen - 1;
		k = 0;
		while (n < nlen) {
			k = klen - 1;
			while (k >= 0) {
				ch = node->orgName[n];
				if (ch >= 'a' && ch <= 'z')
					ch &= ATOUPPER;
				if (ch != orgname[k])
					break;
				n--;
				k--;
			}
			if (k < 0)
				break;
			n += max(bad_char[(uint8_t)ch], good_suffix[k]);
		}
		if (k >= 0)
			continue;
		if (sendRegistryRecord(cb, output, node, type, response))
			return -1;
		output++;
	}
	tst_free(good_suffix);
	if (output == 0) {
		sprintf(response, "No organization found in registry database for org-name=%s\n", orgname);
		if (writestr(cb, response))
			return -1;
	}
	return 0;
}

int getRegistryByOrgName_naive(pwhois_thread_cb * cb, char * orgname, int type)
{
	char response[4096];
	unsigned int i, j, k, output, klen, nlen;
	struct org * node;
	char ch;

	incCounter(CNTR_QUERY_REGTR_ON);
	klen = strlen(orgname);
	for (i = 0; i < klen; i++)
		if (orgname[i] >= 'a' && orgname[i] <= 'z')
			orgname[i] &= ATOUPPER;
	output = 0;
	for (i = 0, node = all_org_records; i < num_org_records; i++, node++) {
		nlen = strlen(node->orgName);
		if (nlen < klen)
			continue;
		for (j = 0; j <= nlen - klen; j++) {
			for (k = 0; k < klen; k++) {
				ch = node->orgName[j+k];
				if (ch >= 'a' && ch <= 'z')
					ch &= ATOUPPER;
				if (ch != orgname[k])
					break;
			}
			if (k == klen)
				break;
		}
		if (j > (nlen - klen))
			continue;
		if (sendRegistryRecord(cb, output, node, type, response))
			return -1;
		output++;
	}
	if (output == 0) {
		sprintf(response, "No organization found in registry database for org-name=%s\n", orgname);
		if (writestr(cb, response))
			return -1;
	}
	return 0;
}

int getRegistryBySourceAS(pwhois_thread_cb * cb, uint32_t srcas, int type)
{
	char response[4096];
	int i;
	uint_fast16_t hash;
	struct asn_ll * asn_curr;
	struct org_list * list;
	unsigned int r;

	incCounter(CNTR_QUERY_REGTR_AS);
	hash = hash32to16(srcas);
	asn_curr = asn_index[hash];
	while (asn_curr != NULL && asn_curr->asn != srcas)
		asn_curr = asn_curr->next;
	if (asn_curr == NULL || asn_curr->as == NULL || asn_curr->as->org_id == NULL)
		list = NULL;
	else {
		hash = hashstringto16(asn_curr->as->org_id, CASE_INSENSITIVE);
		list = orgid_index_org[hash];
	}
	i = 0;
	if (list != NULL)
		for (r = 0; r < list->num; r++) {
			if (strcasecmp(asn_curr->as->org_id, list->org[r]->org_id) != 0)
				continue;
			if (sendRegistryRecord(cb, i, list->org[r], type, response))
				return -1;
			i++;
		}
	if (i == 0) {
		sprintf(response, "No organization found in registry database for source-as=%"PRIu32"\n", srcas);
		if (writestr(cb, response))
			return -1;
	}
	return 0;
}

const char * skip_wsp(const char * str)
{
	for ( ; *str != '\0'; str++)
		if (!isspace(*str))
			break;
	return str;
}

const char * skip_nwsp(const char * str)
{
	for ( ; *str != '\0'; str++)
		if (isspace(*str))
			break;
	return str;
}

/**
 * short version (internally called only) of the registry output method searching by POC handle
 * @param presponse	the response buffer
 * @param pocHandle	the handle to search for
 * @param handleName	the name/type of handle we are printing out for display purposes in the output
 */
int _getRegistryByPOCHandleShort(char * presponse, const char * pocHandle, const char * handleName, int type)
{
	char handle[32], * response = presponse;
	const char * wsp;
	uint_fast16_t hash;
	struct poc_ll * curr;
	unsigned int n, r;

	if (pocHandle == NULL || pocHandle[0] == '\0')
		return 0;
	incDBReference();
	if (!DatabaseIsLoaded) {
		decDBReference();
		return 0;
	}
	pocHandle = skip_wsp(pocHandle);
	for (r = 0; pocHandle[0] != '\0'; r++) {
		wsp = skip_nwsp(pocHandle);
		n = wsp - pocHandle;
		if (n >= sizeof(handle)) {
			pocHandle = skip_wsp(wsp);
			continue;
		}
		memcpy(handle, pocHandle, n);
		handle[n] = '\0';
		pocHandle = skip_wsp(wsp);
		sprintf(presponse, "%s-%d-Handle: %s\n", handleName, r, handle);
		presponse += strlen(presponse);
		if (!type)
			continue;
		hash = hashstringto16(handle, CASE_SENSITIVE);
		curr = pochandle_index[hash];
		while (curr != NULL && (curr->poc == NULL || strcmp(handle, curr->poc->pocHandle) != 0))
			curr = curr->next;
		if (curr == NULL)
			continue;
		if (curr->poc->isrole) {
			if (curr->poc->roleName[0] != '\0') {
				sprintf(presponse, "%s-%d-Role-Name: %s\n", handleName, r, curr->poc->roleName);
				presponse += strlen(presponse);
			}
		} else {
			sprintf(presponse, "%s-%d-Name: ", handleName, r);
			presponse += strlen(presponse);
			if (curr->poc->firstName[0] != '\0') {
				sprintf(presponse, "%s ", curr->poc->firstName);
				presponse += strlen(presponse);
			}
			if (curr->poc->middleName[0] != '\0') {
				sprintf(presponse, "%s ", curr->poc->middleName);
				presponse += strlen(presponse);
			}
			if (curr->poc->lastName[0] != '\0') {
				sprintf(presponse, "%s ", curr->poc->lastName);
				presponse += strlen(presponse);
			}
			sprintf(presponse, "\n");
			presponse += strlen(presponse);
		}
		if (curr->poc->officePhone[0] != '\0') {
			sprintf(presponse, "%s-%d-Phone: %s\n", handleName, r, curr->poc->officePhone);
			presponse += strlen(presponse);
		}
		if (curr->poc->mailbox[0] != '\0') {
			sprintf(presponse, "%s-%d-Email: %s\n", handleName, r, curr->poc->mailbox);
			presponse += strlen(presponse);
		}
	}
	decDBReference();
	return presponse-response;
}

int getRegistryByPOCHandle(pwhois_thread_cb * cb, const char * pocHandle)
{
	char crdt[25], mddt[25], response[4096], * presponse = response;
	int i;
	uint_fast16_t hash;
	struct poc_ll * curr;
	time_t tcrdt, tmddt;

	incCounter(CNTR_QUERY_REGTR_PH);
	hash = hashstringto16(pocHandle, CASE_SENSITIVE);
	curr = pochandle_index[hash];
	while (curr != NULL && (curr->poc == NULL || strcmp(pocHandle, curr->poc->pocHandle) != 0))
		curr = curr->next;
	if (curr == NULL) {
		sprintf(response, "No POC found in registry database for poc-handle=%s\n", pocHandle);
		if (writestr(cb, response))
			return -1;
		return 0;
	}
	sprintf(presponse, "POC Handle: %s\n", pocHandle);
	presponse += strlen(presponse);
	sprintf(presponse, "Is-Role: %i\n", curr->poc->isrole);
	presponse += strlen(presponse);
	if (curr->poc->isrole) {
		if (curr->poc->roleName[0] != '\0') {
			sprintf(presponse, "Role-Name: %s\n", curr->poc->roleName);
			presponse += strlen(presponse);
		}
	} else {
		if (curr->poc->firstName[0] != '\0') {
			sprintf(presponse, "First-Name: %s\n", curr->poc->firstName);
			presponse += strlen(presponse);
		}
		if (curr->poc->middleName[0] != '\0') {
			sprintf(presponse, "Middle-Name: %s\n", curr->poc->middleName);
			presponse += strlen(presponse);
		}
		if (curr->poc->lastName[0] != '\0') {
			sprintf(presponse, "Last-Name: %s\n", curr->poc->lastName);
			presponse += strlen(presponse);
		}
	}
	for (i = 0; i < 6; i++)
		if (curr->poc->street[i][0] != '\0') {
			sprintf(presponse, "Street-%i: %s\n", i + 1, curr->poc->street[i]);
			presponse += strlen(presponse);
		}
	if (curr->poc->city[0] != '\0') {
		sprintf(presponse, "City: %s\n", curr->poc->city);
		presponse += strlen(presponse);
	}
	if (curr->poc->state[0] != '\0') {
		sprintf(presponse, "State: %s\n", curr->poc->state);
		presponse += strlen(presponse);
	}
	if (curr->poc->postalCode[0] != '\0') {
		sprintf(presponse, "Postal-Code: %s\n", curr->poc->postalCode);
		presponse += strlen(presponse);
	}
	if (curr->poc->country[0] != '\0') {
		sprintf(presponse, "Country: %s\n", curr->poc->country);
		presponse += strlen(presponse);
	}
	if (curr->poc->registerDate[0] != '\0') {
		sprintf(presponse, "Register-Date: %s\n", curr->poc->registerDate);
		presponse += strlen(presponse);
	}
	if (curr->poc->updateDate[0] != '\0') {
		sprintf(presponse, "Update-Date: %s\n", curr->poc->updateDate);
		presponse += strlen(presponse);
	}
	tcrdt = curr->poc->createDate;
	if (tcrdt != 0) {
		GetDateTimeFormat(tcrdt, crdt, 25);
		sprintf(presponse, "Create-Date: %s\n", crdt);
		presponse += strlen(presponse);
	}
	tmddt = curr->poc->modifyDate;
	if (tmddt != 0) {
		GetDateTimeFormat(tmddt, mddt, 25);
		sprintf(presponse, "Modify-Date: %s\n", mddt);
		presponse += strlen(presponse);
	}
	if (curr->poc->comment[0] != '\0') {
		sprintf(presponse, "Comment: %s\n", curr->poc->comment);
		presponse += strlen(presponse);
	}
	if (curr->poc->officePhone[0]!= '\0') {
		sprintf(presponse, "Office-Phone: %s\n", curr->poc->officePhone);
		presponse += strlen(presponse);
	}
	if (curr->poc->mailbox[0] != '\0') {
		sprintf(presponse, "Mailbox: %s\n", curr->poc->mailbox);
		presponse += strlen(presponse);
	}
	if (writestr(cb, response))
		return -1;
	return 0;
}

int sendRouteHeader(pwhois_thread_cb * cb, char * response, int as)
{
	sprintf(response, "    Prefix            | Create-Date              | Modify-Date              | Next-Hop        %s| AS-Path\n", as ? "| Origin-AS  " : "");
	if (writestr(cb, response))
		return -1;
	return 0;
}

int sendRouteLine(pwhois_thread_cb * cb, struct route * route, char * response, int as)
{
	char host[20], network[25], crdt[25], mddt[25];

	sprintf(network, "%s/%d", ipv4_decimal_to_quaddot(route->prefix, host, 20), route->cidr);
	GetDateTimeFormat(route->createDate, crdt, 25);
	GetDateTimeFormat(route->modifyDate, mddt, 25);
	if (as)
		sprintf(response, "%c%c %18s | %24s | %24s | %15s | %10i | %s\n", (route->status == 0) ? 'N' : '*', (route->best_route == 0) ? ' ' : '>', network, crdt, mddt, ipv4_decimal_to_quaddot(route->next_hop, host, 20), route->asn, route->asnPaths);
	else
		sprintf(response, "%c%c %18s | %24s | %24s | %15s | %s\n", (route->status == 0) ? 'N' : '*', (route->best_route == 0) ? ' ' : '>', network, crdt, mddt, ipv4_decimal_to_quaddot(route->next_hop, host, 20), route->asnPaths);
	if (writestr(cb, response))
		return -1;
	return 0;
}

int sendTransitRouteHeader(pwhois_thread_cb * cb, char * response)
{
    sprintf(response, "    Prefix            | Origin-AS  | Org-Name                       | AS-Org-Name                    | CC | AS-Path\n");
    if (writestr(cb, response))
        return -1;
    return 0;
}

int sendTransitRouteLine(pwhois_thread_cb * cb, struct route * route, char * orgName, char * as_orgName, char * cc, char * response)
{
    char host[20], network[25];
    
    sprintf(network, "%s/%d", ipv4_decimal_to_quaddot(route->prefix, host, 20), route->cidr);
    sprintf(response, "%c%c %18s | %10i | %30s | %30s | %2s | %s\n", (route->status == 0) ? 'N' : '*', (route->best_route == 0) ? ' ' : '>', network, route->asn, orgName, as_orgName, cc, route->asnPaths);
    if (writestr(cb, response))
        return -1;
    return 0;
}

int getRouteviewBySourceAS(pwhois_thread_cb * cb, int bestonly, uint32_t srcas)
{
	unsigned int n, i = 0;
	struct asn_ll * asn_curr;
	struct route_list * list;
	struct route * route;
	char response[512];

	incCounter(CNTR_QUERY_RVIEW_AS);
	asn_curr = asn_index[hash32to16(srcas)];
	while (asn_curr != NULL && asn_curr->asn != srcas)
		asn_curr = asn_curr->next;
	if (asn_curr != NULL) {
		list = asn_curr->list;
		if (list != NULL) {
			n = list->num;
			while (n > 0 && (!bestonly || (list->route[n-1]->status != 0 && list->route[n-1]->best_route != 0)) && (!UseRouterFilter || RouterFilter == list->route[n-1]->routerID)) {
				route = list->route[n-1];
				if(i == 0) {
					sprintf(response,	"Origin-AS: %"PRIu32"\n", srcas);
					if (writestr(cb, response) || sendRouteHeader(cb, response, 0))
						return -1;
				}
				if (sendRouteLine(cb, route, response, 0))
					return -1;
				n--;
				i++;
			}
		}
	}
	if(i == 0)
	{
		sprintf(response, "No prefixes found in routeview database for source-as=%"PRIu32"\n", srcas);
		if (writestr(cb, response))
			return -1;
	}
	return 0;
}

int getRouteviewByTransitAS(pwhois_thread_cb * cb, int bestonly, uint32_t trnas)
{
    unsigned int n, i = 0, j;
    struct asn_ll * asn_curr;
    struct route_list * list;
    struct route * route;
    char response[512];
    // whois request vars
    int result;
    uint32_t asn, next_hop, as_orgNameSrc=0, orgNameSrc=0, netNameSrc=0;
    time_t tcrdt, tmddt;
    char ipcidr[20], quaddot[20], network[50], asnPaths[256], as_orgName[130], orgName[130], netName[70];
    geo_iprange * geo;
    struct org_list * orglist;
    unsigned int orgfirst;
    struct netblock * net;
    struct asn * as;
    char * cc;
    
    incCounter(CNTR_QUERY_RVIEW_TAS);
    asn_curr = asn_index[hash32to16(trnas)];
    while (asn_curr != NULL && asn_curr->asn != trnas)
        asn_curr = asn_curr->next;
    if (asn_curr != NULL) {
        for (j=0; j<=1; j++) {
            list = (j == 0) ? asn_curr->list: asn_curr->transit_list;
            if (list != NULL) {
                n = list->num;
                while (n > 0 && (!bestonly || (list->route[n-1]->status != 0 && list->route[n-1]->best_route != 0)) && (!UseRouterFilter || RouterFilter == list->route[n-1]->routerID)) {
                    route = list->route[n-1];
                    ipv4_decimal_to_quaddot(route->prefix, quaddot, 20);
                    snprintf(ipcidr, 20, "%s/%d", quaddot, route->cidr);
                    
                    // whois request for as_orgName and orgName
                    result=handleWhoisRequest(ipcidr, network, &asn, asnPaths, &tcrdt, &tmddt, &next_hop, as_orgName, &as_orgNameSrc, orgName, &orgNameSrc, netName, &netNameSrc, &geo, &orglist, &orgfirst, &net, &as);
                    if (!result) {
                        snprintf(as_orgName, 130, "NULL");
                        snprintf(orgName, 130, "NULL");
                    }
                    // geoLookup for country code. treat prefix as unicast. slightly redundant. first call to geo in handleWhoisRequest has cidr and is therefore skipped
                    geo=FindIPRange(route->prefix);
                    cc = "NULL";
                    if (geo != NULL && geo->location->region->country->shortname[0] != '-')
                        cc = geo->location->region->country->shortname;
                    
                    if(i == 0) {
                        snprintf(response, 512, "Transit-AS: %"PRIu32"\n", trnas);
                        if (writestr(cb, response) || sendTransitRouteHeader(cb, response))
                            return -1;
                    }
                    if (sendTransitRouteLine(cb, route, orgName, as_orgName, cc, response))
                        return -1;
                    n--;
                    i++;
                }
            }
        }
    }
    if(i == 0)
    {
        snprintf(response, 512, "No prefixes found in routeview database for transit-as=%"PRIu32"\n", trnas);
        if (writestr(cb, response))
            return -1;
    }
    return 0;
}

int getRouteviewByPrefix(pwhois_thread_cb * cb, int bestonly, char * ip, int cidr)
{
	prefix_t * prefix;
	patricia_node_t * pnode;
	struct routes * rlist;
	struct route * rnode;
	uint32_t ipaddr;
	char response[512], ipcidr[25];
	int best_route, status, i = 0;
	unsigned int n;

	incCounter(CNTR_QUERY_RVIEW_PX);
	if (ipv4_quaddot_to_decimal(ip, &ipaddr))
		return -1;
	ipaddr = htonl(ipaddr);
	if (cidr == 0)
		cidr = 32;
	prefix = New_Prefix(AF_INET, &ipaddr, cidr);
	pnode = patricia_search_best(pTreeRoutes, prefix);
	Deref_Prefix(prefix);
	if (pnode == NULL) {
		sprintf(response,"Route for %s not found in the global routing table\n", ip);
		if (writestr(cb, response))
			return -1;
		return 0;
	}
	rlist = pnode->data;
	sprintf(ipcidr, "%s/%d", prefix_toa(pnode->prefix), pnode->prefix->bitlen);
	for (status = 1; status >= (bestonly != 0); status--)
		for (best_route = 1; best_route >= (bestonly != 0); best_route--) {
			n = 0;
			while (rlist->routes[best_route][status] != NULL && n < rlist->routes[best_route][status]->num) {
				rnode = rlist->routes[best_route][status]->route[n];
				if (UseRouterFilter && RouterFilter != rnode->routerID)
					continue;
				if (i == 0) {
					sprintf(response,	"Origin-AS: %"PRIu32"\n", rnode->asn);
					if (writestr(cb, response) || sendRouteHeader(cb, response, 0))
						return -1;
				}
				if (sendRouteLine(cb, rnode, response, 0))
					return -1;
				i++;
				n++;
			}
		}
	if (i == 0) {
		sprintf(response, "No prefixes found in routeview database for prefix=%s\n", ipcidr);
		if (writestr(cb, response))
			return -1;
	}
	return 0;
}

int getRouteviewByOrgName(pwhois_thread_cb * cb, int bestonly, char * orgname)
{
	char response[512], ch;
	unsigned int i, j, k, klen, nlen, output_as, output_route;
	struct asn_count * node;
	struct asn_ll * curr;
	struct route * route;

	incCounter(CNTR_QUERY_RVIEW_ON);
	klen = strlen(orgname);
	for (i = 0; i < klen; i++)
		if (orgname[i] >= 'a' && orgname[i] <= 'z')
			orgname[i] &= ATOUPPER;
	output_as = 0;
	for (i = 0, node = asn_stats; i < num_asn_stats; i++, node++) {
		nlen = strlen(node->orgName);
		if (nlen < klen)
			continue;
		for (j = 0; j <= nlen - klen; j++) {
			for (k = 0; k < klen; k++) {
				ch = node->orgName[j+k];
				if (ch >= 'a' && ch <= 'z')
					ch &= ATOUPPER;
				if (ch != orgname[k])
					break;
			}
			if (k == klen)
				break;
		}
		if (j > (nlen - klen))
			continue;
		curr = asn_index[hash32to16(node->asn)];
		while (curr != NULL && curr->asn != node->asn)
			curr = curr->next;
		if (curr == NULL || curr->list == NULL)
			continue;
		sprintf(response, "Record: %i\nOrg-Name: %s\nOrigin-AS: %"PRIu32"\n", output_as, node->orgName, node->asn);
		if (writestr(cb, response) || sendRouteHeader(cb, response, 0))
			return -1;
		output_route = 0;
		for (j = curr->list->num; j > 0 && (!bestonly || (curr->list->route[j-1]->status != 0 && curr->list->route[j-1]->best_route != 0)) && (!UseRouterFilter || RouterFilter == curr->list->route[j-1]->routerID); j--) {
			route = curr->list->route[j-1];
			if (sendRouteLine(cb, route, response, 0))
				return -1;
			output_route++;
		}
		output_as++;
	}
	if (output_as == 0) {
		sprintf(response, "No AS found in routeview database for org-name=%s\n", orgname);
		if (writestr(cb, response))
			return -1;
	}
	return 0;
}

int getRouteviewByNextHop(pwhois_thread_cb * cb, int bestonly, char * nexthopstr)
{
	char response[512];
	uint32_t next_hop;
	unsigned int i;
	int best_route, status;
	struct route * node;

	incCounter(CNTR_QUERY_RVIEW_NH);
	if (ipv4_quaddot_to_decimal(nexthopstr, &next_hop) || sendRouteHeader(cb, response, 1))
		return -1;
	for (status = 1; status >= (bestonly != 0); status--)
		for (best_route = 1; best_route >= (bestonly != 0); best_route--)
			for (i = 0, node = all_route_records[best_route][status] + num_route_records[best_route][status] - 1; i < num_route_records[best_route][status]; i++, node--)
				if (node->next_hop == next_hop && sendRouteLine(cb, node, response, 1))
					return -1;
	return 0;
}

int getRouteviewASCount(pwhois_thread_cb * cb)
{
	char response[256];
	unsigned int i;
	
	incCounter(CNTR_QUERY_RVIEW_AC);
	sprintf(response, "Total-AS-Count: %i\nPrefixes |    ASN    |  Country  | Org-Name\n", num_asn_stats);
	if (writestr(cb, response))
		return -1;
	for (i = 0; i < num_asn_stats; i++) {
		sprintf(response, "%8i | %9i | %9s | %s\n", asn_stats[i].count, asn_stats[i].asn, asn_stats[i].country[0] == '\0' ? "<missing>" : asn_stats[i].country, asn_stats[i].orgName[0] == '\0' ? "<Missing record>" : asn_stats[i].orgName);
		if (writestr(cb, response))
			return -1;
	}
	return 0;
}

int getRouteviewASPrivate(pwhois_thread_cb * cb, int bestonly)
{
	char response[512];
	unsigned int i;
	int best_route, status;
	struct route * node;

	incCounter(CNTR_QUERY_RVIEW_AP);
	if (sendRouteHeader(cb, response, 1))
		return -1;
	for (status = 1; status >= (bestonly != 0); status--)
		for (best_route = 1; best_route >= (bestonly != 0); best_route--)
			for (i = 0, node = all_route_records[best_route][status] + num_route_records[best_route][status] - 1; i < num_route_records[best_route][status]; i++, node--)
				if (node->asn >= 64512 && node->asn <= 65534 && sendRouteLine(cb, node, response, 1))
					return -1;
	return 0;
}

int getRouteviewASReserved(pwhois_thread_cb * cb, int bestonly)
{
	char response[512];
	unsigned int i;
	int best_route, status;
	struct route * node;

	incCounter(CNTR_QUERY_RVIEW_AR);
	if (sendRouteHeader(cb, response, 1))
		return -1;
	for (status = 1; status >= (bestonly != 0); status--)
		for (best_route = 1; best_route >= (bestonly != 0); best_route--)
			for (i = 0, node = all_route_records[best_route][status] + num_route_records[best_route][status] - 1; i < num_route_records[best_route][status]; i++, node--)
				if ((node->asn == 0 || (node->asn >= 64496 && node->asn <= 64511) || (node->asn >= 65535 && node->asn <= 131071) || node->asn == 4294967295) && sendRouteLine(cb, node, response, 1))
					return -1;
	return 0;
}

int getRouteviewNew(pwhois_thread_cb * cb, int bestonly, int seconds)
{
	char response[512];
	unsigned int i;
	int best_route;
	struct route * node;

	incCounter(CNTR_QUERY_RVIEW_N);
	if (sendRouteHeader(cb, response, 1))
		return -1;
	for (best_route = 1; best_route >= (bestonly != 0); best_route--)
		for (i = 0, node = all_route_records[best_route][1] + num_route_records[best_route][1] - 1; i < num_route_records[best_route][1]; i++, node--)
			if ((node->createDate > (lastTableUpdate - seconds) || seconds < 0) && sendRouteLine(cb, node, response, 1))
				return -1;
	return 0;
}

int getRouteviewPurged(pwhois_thread_cb * cb, int bestonly, int seconds)
{
	char response[512];
	unsigned int i;
	int best_route;
	struct route * node;

	incCounter(CNTR_QUERY_RVIEW_P);
	if (sendRouteHeader(cb, response, 1))
		return -1;
	for (best_route = 1; best_route >= (bestonly != 0); best_route--)
		for (i = 0, node = all_route_records[best_route][0] + num_route_records[best_route][0] - 1; i < num_route_records[best_route][0]; i++, node--)
			if ((node->modifyDate > (lastTableUpdate - seconds) || seconds < 0) && sendRouteLine(cb, node, response, 1))
				return -1;
	return 0;
}

int getStandardQueryResponse(pwhois_thread_cb * cb, int type, int datatype, char * ip, char * ipcidr, char * extra)
{
	int result;
	uint32_t asn, next_hop, as_orgNameSrc=0, orgNameSrc=0, netNameSrc=0;
	time_t tcrdt, tmddt;
	char network[50], asnPaths[256], as_orgName[130], orgName[130], netName[70];
	char ltupddate[30], response[4096], cshdate[30], crdt[25], mddt[25], host[20];
	geo_iprange * geo;
	int cidrisdefined, i;
	struct org_list * orglist;
	unsigned int orgfirst, r;
	struct netblock * net;
	struct asn * as;
	
	incCounter(CNTR_QUERY_PWHOIS);
	log_printf(4, "getStandardQueryResponse checkpoint 1\n");
	cidrisdefined=strcmp(ip,ipcidr);
	log_printf(4, "getStandardQueryResponse checkpoint 2\n");
	response[0]=0;
	if(type==PW_CYMRU && (!cb->bulk || (cb->bulk && cb->bulkCount <= 1)))
	{
		//return header
		GetCymruDateFormat(CurrentTime(), ltupddate, 30);
		if(cb->bulk)
			sprintf(response+strlen(response), "Bulk mode; one IP per line. [%s]\n",ltupddate);
		sprintf(response+strlen(response), "AS      | IP               | ORG NAME                      | CC | NET NAME                         | AS ORG NAME\n");
	}
	log_printf(4, "getStandardQueryResponse checkpoint 3\n");
	result=handleWhoisRequest(ipcidr, network, &asn, asnPaths, &tcrdt, &tmddt, &next_hop, as_orgName, &as_orgNameSrc, orgName, &orgNameSrc, netName, &netNameSrc, &geo, &orglist, &orgfirst, &net, &as);
	log_printf(4, "getStandardQueryResponse checkpoint 4\n");
	if(!result)
	{
		if(cb->bulk)
		{
			switch(type)
			{
				case PW_CYMRU:
						sprintf(response+strlen(response), "%-7s | %-16s | %-29.29s | %-2s | %-32s | %s\n", "NA", ip, "NA", "-", "NA", "NA");
					break;
				case PW_RPSL:
					sprintf(response+strlen(response), "No matching data found\n");
					break;
				case PW_PWHOIS:
				default:
					if(cb->bulkCount > 1)
						sprintf(response+strlen(response), 
								"\nIP: %s\nOrigin-AS: NULL\nPrefix: NULL\nAS-Path: NULL\nAS-Org-Name: NULL\nOrg-Name: NULL\nNet-Name: NULL\nCache-Date: NULL\n",
								ip);
					else
						sprintf(response+strlen(response), 
								"IP: %s\nOrigin-AS: NULL\nPrefix: NULL\nAS-Path: NULL\nAS-Org-Name: NULL\nOrg-Name: NULL\nNet-Name: NULL\nCache-Date: NULL\n",
								ip);
					if(!cidrisdefined)
						sprintf(response+strlen(response), "Latitude: 0\nLongitude: 0\nCity: NULL\nRegion: NULL\nCountry: NULL\nCountry-Code: NULL\n");
					if(datatype == PW_DATA_ALL) {
						sprintf(response+strlen(response), "AS-Org-Name-Source: NULL\nOrg-Name-Source: NULL\nNet-Name-Source: NULL\nCreate-Date: NULL\nModify-Date: NULL\nNext-Hop: NULL\n");
						// add more fields here as they become available
					}
					if(strlen(extra))
						sprintf(response+strlen(response), "Info: %s\n",extra);
					break;
			}
		}
		else
		{
			if(type==PW_CYMRU)
				sprintf(response+strlen(response), "%-7s | %-16s | %-29.29s | %-2s | %-32s | %s\n", "NA", ip, "NA", "-", "NA", "NA");
			else
			{
				GetDateTimeFormat(lastTableUpdate, ltupddate, 25);
				sprintf(response, "That IP address doesn't appear in the global routing table as of %s\n",ltupddate);
			}
		}
		if(writestr(cb, response))
			return -1;
		
		return 0;
	}
	GetDateTimeFormat(tcrdt, crdt, 25);
	GetDateTimeFormat(tmddt, mddt, 25);
	log_printf(4, "getStandardQueryResponse checkpoint 5\n");
	switch(type)
	{
		case PW_CYMRU:
			if(!strlen(as_orgName))
				strcpy(as_orgName, "NA");
			i = strlen(netName);
			if (i) {
				if (i > 32 - 3)
					strcpy(netName + 32 - 3, "...");
			} else
				strcpy(netName, "NA");
			if(!strlen(orgName))
				strcpy(orgName, "NA");
			log_printf(4, "getStandardQueryResponse checkpoint 5b\n");
			sprintf(response+strlen(response), "%-7"PRIu32" | %-16s | %-29.29s | %-2s | %-32s | %s\n", asn, ip, orgName, geo == NULL ? "-" : geo->location->region->country->shortname, netName, as_orgName);
			log_printf(4, "getStandardQueryResponse checkpoint 5c\n");
			break;
		case PW_RPSL:
			GetRpslDateFormat(cacheDate, cshdate, 30);
			sprintf(response+strlen(response), "Origin: AS%"PRIu32"\nRoute: %s\nDate: %s\nAS-Org-Name: %s\nOrg-Name: %s\nNet-Name: %s\nSource: PWHOIS Server %s:%d at %s\n",
					asn, network, cshdate, as_orgName, orgName, netName, cb->localIp, cb->localPort, cshdate);
			if(strlen(extra))
				sprintf(response+strlen(response), "Info: %s\n",extra);
			break;
		case PW_PWHOIS:
		default:
			if(cb->bulkCount > 1)
				sprintf(response+strlen(response), "\n");
			if(datatype == PW_DATA_NORMAL || datatype == PW_DATA_UNKNOWN || datatype == PW_DATA_ALL) {
				sprintf(response+strlen(response), "IP: %s\nOrigin-AS: %"PRIu32"\nPrefix: %s\nAS-Path: %s\nAS-Org-Name: %s\nOrg-Name: %s\nNet-Name: %s\nCache-Date: %lu\n",
					ip, asn, network, asnPaths, as_orgName, orgName, netName, cacheDate);
			}
			if(!cidrisdefined)
			{
				if(geo != NULL)
					sprintf(response+strlen(response), "Latitude: %f\nLongitude: %f\nCity: %s\nRegion: %s\nCountry: %s\nCountry-Code: %s\n",
							geo->location->latitude, geo->location->longitude, geo->location->city[0] == '-' ? "NULL" : geo->location->city, geo->location->region->region[0] == '-' ? "NULL" : geo->location->region->region, geo->location->region->country->longname[0] == '-' ? "NULL" : geo->location->region->country->longname, geo->location->region->country->shortname[0] == '-' ? "NULL" : geo->location->region->country->shortname);
				else
					sprintf(response+strlen(response), "Latitude: 0\nLongitude: 0\nCity: NULL\nRegion: NULL\nCountry: NULL\nCountry-Code: NULL\n");
			}
			if(datatype == PW_DATA_ALL) {
				sprintf(response+strlen(response), "AS-Org-Name-Source: %s\nOrg-Name-Source: %s\nNet-Name-Source: %s\nRoute-Create-Date: %s\nRoute-Modify-Date: %s\nNext-Hop: %s\n", GET_SOURCE_NAME(as_orgNameSrc), GET_SOURCE_NAME(orgNameSrc), GET_SOURCE_NAME(netNameSrc), crdt, mddt, ipv4_decimal_to_quaddot(next_hop, host, 20));
				// add more fields here as they become available
				if (as != NULL) {
					if (as->mailbox[0] != '\0')
						sprintf(response+strlen(response), "AS-Mailbox: %s\n", as->mailbox);
					if (as->adminHandle[0] != '\0') {
						if (writestr(cb, response))
							return -1;
						_getRegistryByPOCHandleShort(response, as->adminHandle, "AS-Admin", 1);
					}
					if (as->techHandle[0] != '\0') {
						if (writestr(cb, response))
							return -1;
						_getRegistryByPOCHandleShort(response, as->techHandle, "AS-Tech", 1);
					}
				}
				if (net != NULL) {
					if (writestr(cb, response))
						return -1;
					sprintf(response, "Net-Range: %s - %s\n", ipv4_decimal_to_quaddot(net->network, network, 20), ipv4_decimal_to_quaddot(net->enetrange, host, 20));
					sprintf(response+strlen(response), "Net-Type: %s\n", getNetType(net->netType));
					GetDateTimeFormat(net->createDate, crdt, 25);
					GetDateTimeFormat(net->modifyDate, mddt, 25);
					sprintf(response+strlen(response), "Net-Register-Date: %s\nNet-Update-Date: %s\nNet-Create-Date: %s\nNet-Modify-Date: %s\n", net->registerDate, net->updateDate, crdt, mddt);
					if (net->mailbox[0] != '\0')
						sprintf(response+strlen(response), "Net-Mailbox: %s\n", net->mailbox);
					if (net->nocHandle[0] != '\0') {
						if (writestr(cb, response))
							return -1;
						_getRegistryByPOCHandleShort(response, net->nocHandle, "Net-NOC", 1);
					}
					if (net->abuseHandle[0] != '\0') {
						if (writestr(cb, response))
							return -1;
						_getRegistryByPOCHandleShort(response, net->abuseHandle, "Net-Abuse", 1);
					}
					if (net->techHandle[0] != '\0') {
						if (writestr(cb, response))
							return -1;
						_getRegistryByPOCHandleShort(response, net->techHandle, "Net-Tech", 1);
					}
				}
				i = 0;
				if (orglist != NULL) {
					r = orgfirst;
					while (r < orglist->num) {
						if (writestr(cb, response))
							return -1;
						prepareRegistryRecord(response, i, orglist->org[r], 1);
						do {
							r++;
						} while (r < orglist->num && strcasecmp(orglist->org[orgfirst]->org_id, orglist->org[r]->org_id) != 0);
						i++;
					}
				}
			}
			if(strlen(extra))
				sprintf(response+strlen(response), "Info: %s\n",extra);
			break;
	}
	log_printf(4, "getStandardQueryResponse checkpoint 6\n");
	if(writestr(cb, response))
		return -1;
	log_printf(4, "getStandardQueryResponse checkpoint 7\n");
	return 0;
}

int getAllStatisticsStep(struct ip * ip, pwhois_thread_cb * cb)
{
    char response[512];
    char ipstr[20];
    char fq[26],lq[26];

    // status=3 means hidden, suppress display of this ACL entry
    if (ip->acl==3)
        return 0;
    if(ip->acl>=1)
        response[0]='+';
    else
        response[0]='-';
    sprintf(ipstr,"%u.%u.%u.%u",(int)ip->ip[0],(int)ip->ip[1],(int)ip->ip[2],(int)ip->ip[3]);
	if (ip->lastQuery == 0) {
		sprintf(fq, "N/A");
		sprintf(lq, "N/A");
	} else {
		GetDateTimeFormat(ip->firstQuery, fq, 25);
		GetDateTimeFormat(ip->lastQuery, lq, 25);
	}
    sprintf(response+1,"> %15s | %4d | %10d | %10d | %24s | %24s\n", ipstr, ip->cidr, ip->count, ip->limit, fq, lq);
    if (writestr(cb, response))
		return -1;
	return 0;
}

int getStatistics(pwhois_thread_cb * cb, int all)
{
    char response[1024];
    int error=0;
	sprintf(response,
        "Server Statistics:\n"
        "                   Unique IPs: %lu\n"
		"                Whois Queries: %lu\n"
		"     Routeview Prefix Queries: %lu\n"
		"  Routeview Source-AS Queries: %lu\n"
        " Routeview Transit-AS Queries: %lu\n"
		"   Routeview Org-Name Queries: %lu\n"
		"   Routeview Next-Hop Queries: %lu\n"
		"   Routeview AS-Count Queries: %lu\n"
		" Routeview AS-Private Queries: %lu\n"
		"Routeview AS-Reserved Queries: %lu\n"
		"        Routeview New Queries: %lu\n"
		"     Routeview Purged Queries: %lu\n"
		"   Netblock Source-AS Queries: %lu\n"
		"      Netblock Org-ID Queries: %lu\n"
		"      Registry Org-ID Queries: %lu\n"
		"    Registry Org-Name Queries: %lu\n"
		"   Registry Source-AS Queries: %lu\n"
		"         Registry POC Queries: %lu\n"
		"      Registry E-Mail Queries: %lu\n"
		"                Peers Queries: %lu\n"
        "               Milter Queries: %lu\n"
        "                 MSIO Queries: %lu\n"
        "             Fail2Ban Queries: %lu\n"
		"           Active Connections: %lu\n\n",
        getCounter(CNTR_UNIQUE_PEERS),
        getCounter(CNTR_QUERY_PWHOIS),
        getCounter(CNTR_QUERY_RVIEW_PX),
        getCounter(CNTR_QUERY_RVIEW_AS),
        getCounter(CNTR_QUERY_RVIEW_TAS),
		getCounter(CNTR_QUERY_RVIEW_ON),
		getCounter(CNTR_QUERY_RVIEW_NH),
		getCounter(CNTR_QUERY_RVIEW_AC),
		getCounter(CNTR_QUERY_RVIEW_AP),
		getCounter(CNTR_QUERY_RVIEW_AR),
		getCounter(CNTR_QUERY_RVIEW_N),
		getCounter(CNTR_QUERY_RVIEW_P),
        getCounter(CNTR_QUERY_NBLCK_AS),
        getCounter(CNTR_QUERY_NBLCK_OI),
        getCounter(CNTR_QUERY_REGTR_OI),
        getCounter(CNTR_QUERY_REGTR_ON),
        getCounter(CNTR_QUERY_REGTR_AS),
        getCounter(CNTR_QUERY_REGTR_PH),
		getCounter(CNTR_QUERY_REGTR_EM),
        getCounter(CNTR_QUERY_PEERS),
        getCounter(CNTR_QUERY_MILTER),
        getCounter(CNTR_QUERY_MSIO),
        getCounter(CNTR_QUERY_FAIL2BAN),
		getCounter(CNTR_ACTIVE_CONN));

    if (writestr(cb, response))
		return -1;
    if(all)
    {
		sprintf(response, "Allocated memory size: %lu\n", tst_allocated());
        if (writestr(cb, response))
		    return -1;
        sprintf(response,
            "Cache/ACL Statistics:\n"
            "     Unique IPs: %lu\n\n"
            "   IP              | CIDR | Count      | Limit      | First                    | Last\n",
            getCounter(CNTR_UNIQUE_PEERS));
        if (writestr(cb, response))
		    return -1;
        process_all_requests(&error, (process_ip)getAllStatisticsStep, (void *)cb);
    }
    return error;
}

int has_capture(regmatch_t * match, int idx)
{
    if(match[idx].rm_so==-1 && match[idx].rm_eo==-1)
        return 0;
    return 1;
}

void extract_capture(regmatch_t * match, int idx, char * text, char * whereto, size_t sz)
{
    char tmp;
    if(match[idx].rm_so==-1 && match[idx].rm_eo==-1)
        whereto[0]=0;
    else
    {
        tmp=text[match[idx].rm_eo];
        text[match[idx].rm_eo]=0;
        strncpy(whereto,text+match[idx].rm_so,sz);
        text[match[idx].rm_eo]=tmp;
    }
}

int compare_capture(regmatch_t * match, int idx, char * text, char * substr)
{
    char tmp[301];
    extract_capture(match, idx, text, tmp, 300);
    return strcmp(tmp,substr);
}

int space_trimmed_strlen(char * str)
{
	char *p;
	for(p=str; *p && isspace(*p); p++)
		continue;
	if(*p)
		return strlen(p);
	return 0;
}

int check_acl(pwhois_thread_cb * cb)
{
	regmatch_t args[10];

	if(!cb->currentACL->acl)
	{
		log_printf(0, "Peer: %s is blocked from database access by ACL\n",cb->peerIp);
		writen(cb->sock,MSG_ACCESS_DENIED,strlen(MSG_ACCESS_DENIED));
		return 0;
	}
	if (parse_req("^PWhois-Milter-v([0-9]+\\.)+[0-9]+ ([A-Za-z0-9-]+\\.)+([A-Za-z0-9]){2,} (.*)$", cb->application, args, 10)) {
        incCounter(CNTR_QUERY_MILTER);
        if (cb->currentACL->count < MILTER_MAX_QUERIES) {
            log_printf(1, "Relaxing ACL limit for PWhois Milter.  Total queries so far: %i\n", cb->currentACL->count + 1);
            return 1;
        }
	}
	if (parse_req("^MsgSafe.io-([0-9]+\\.)+[0-9]+(.*)$", cb->application, args, 10)) {
		incCounter(CNTR_QUERY_MSIO);
		if (cb->currentACL->count < MILTER_MAX_QUERIES) {
			log_printf(1, "Relaxing ACL limit for MSIO.  Total queries so far: %i\n", cb->currentACL->count + 1);
			return 1;
		}
	}
	if (parse_req("^fail2ban:[A-Za-z0-9_*/.+-]+", cb->application, args, 10)) {
		incCounter(CNTR_QUERY_FAIL2BAN);
		if (cb->currentACL->count < FAIL2BAN_MAX_QUERIES) {
			log_printf(1, "Relaxing ACL limit for Fail2Ban.  Total queries so far: %i\n", cb->currentACL->count + 1);
			return 1;
		}
	}
	if(cb->currentACL->count >= cb->currentACL->limit)
	{
		log_printf(0, "Peer IP: %s - %s",cb->peerIp,MSG_LIMIT_EXCEEDED);
		writen(cb->sock,MSG_LIMIT_EXCEEDED,strlen(MSG_LIMIT_EXCEEDED));
		cb->bulk=0;
		return 0;
	}
	return 1;
}

void increment_acl(pwhois_thread_cb * cb)
{
	cb->currentACL->count++;
	cb->reqcount++;
	if (cb->bulk)
		cb->bulkCount++;
	cb->currentACL->lastQuery = cb->lastRegTime;
}

int parse_and_execute(char * req, pwhois_thread_cb * cb)
{
	regmatch_t args[30];
    char tmp[301];
    char response[2000];
	int retval = -1;

	log_printf(1, "Received from %s: \"%s\"\n",cb->peerIp, req);
    if(parse_req("^ *app *= *\"?([A-Za-z0-9.[:space:]_():;/*+\\-]+)\"? *(.*)$", req, args, 30))		// on a line by itself
    {
		cb->attribute=1;	// attribute
		if (cb->application[0] != '\0') {
			writestr(cb, MSG_INVALIDINPUT);
			return -1;
		}
        //1-appname
        extract_capture(args, 1, req, cb->application, 255);
		//log_printf(1, "Application='%s'\n", cb->application);
		if(!has_capture(args, 2))
			return 0;
		extract_capture(args, 2, req, tmp, 300);
		if(!space_trimmed_strlen(tmp))	//if empty string
			return 0;
		strncpy(req,tmp,300);
    }
	report_write(cb, req);
	if(parse_req("^ *(bulk|begin) *$", req, args, 30))
	{
		cb->attribute=0;	// command
		if (cb->bulk) {
			writestr(cb, MSG_INVALIDINPUT);
			return -1;
		}
		//start bulk request
        cb->bulk=1;
        return 0;
	}
	if(req[0] == '\0' || parse_req("^ *(end|quit) *$", req, args, 30))
	{
		cb->attribute=0;	// command
		if (!cb->bulk) {
			writestr(cb, MSG_INVALIDINPUT);
			return -1;
		}
		//end bulk request
        cb->bulk=0;
        return 0;
	}
	if (!check_acl(cb)) {
		increment_acl(cb);
		return -1;
	}
    if(parse_req("^ *type=(pwhois|cymru|rpsl|all) *$", req, args, 30))
    {
		cb->attribute=1;	// attribute
		
		extract_capture(args, 1, req, tmp, 300);
		if(!strcmp(tmp,"cymru"))
			cb->displayType=PW_CYMRU;
		else
			if(!strcmp(tmp,"rpsl"))
				cb->displayType=PW_RPSL;
			else {
				cb->displayType=PW_PWHOIS;
				if (!strcmp(tmp,"all"))
					cb->dataType=PW_DATA_ALL;
				else
					cb->dataType=PW_DATA_NORMAL;
			}
		return 0;
    }
	increment_acl(cb);
	if(parse_req("^ *(help|\\?) *$", req, args, 30))
	{
		//help
        if (writestr(cb, text_help))
		    return -1;
		cb->bulk=0;
        return 0;
	}
	if(parse_req("^ *(peers) *$", req, args, 30))
	{
		cb->attribute=0;	// command
		
		char buf[30], * pbuf;
		unsigned long i;

		if (incDBReferenceAndLock(cb))
			return -1;
		incCounter(CNTR_QUERY_PEERS);
		for(i=0;i<peersCounter;i++)
		{
			getPeerIP(i, buf);
			pbuf=buf+strlen(buf);
			pbuf[0]='\n';
			pbuf[1]=0;
			if (writestr(cb, buf))
			{
				decDBReference();
				return -1;
			}
		}
		decDBReference();
		cb->bulk=0;
		return 0;
	}
	if(parse_req("^ *(extra-help) *$", req, args, 30))
	{
		cb->attribute=0;	// command

		//help
        if (writestr(cb, text_help))
		    return -1;
		//extra-help
        if (writestr(cb, text_extra_help))
		    return -1;
		cb->bulk=0;
        return 0;
	}
	if(parse_req("^ *(version) *$", req, args, 30))
	{
		cb->attribute=0;	// command

		//version
        getVersionRuntime(response, 2000);
        if (writestr(cb, response))
		    return -1;
		cb->bulk=0;
        return 0;
    }
	if(parse_req("^ *((type=(all)) +)?(statistics) *$", req, args, 30))
	{
		cb->attribute=0;	// command
		cb->bulk=0;
		//statistics
        if(args[3].rm_so==-1 && args[3].rm_eo==-1)
            return getStatistics(cb, 0);
        else
            return getStatistics(cb, 1);
	}
    if(parse_req("^ *(type=(all|best) +)?routeview +(((source|transit)-as=([[:digit:]]{1,10}))|(prefix=([[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3})(/([[:digit:]]{1,2}))?)|(org-name=\"?([(),\\. A-Za-z0-9_\\-]{3,})\"?)|(next-hop=([[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3}))|(as-count)|(as-private)|(as-reserved)|(new=([[:digit:]]{1,7}))|(purged=([[:digit:]]{1,7}))|(dump)) *$", req, args, 30))
    {
		cb->attribute=0;	// command

        //2-type, 6-(source|transit)-as, 8-prefix, 10-cidr
        int bestonly,cidr;
		if (incDBReferenceAndLock(cb))
			return -1;
        if(has_capture(args, 2) && !compare_capture(args, 2, req, "all"))
            bestonly=0;
        else
            bestonly=1;
        if (has_capture(args, 6)) {
            extract_capture(args, 6, req, tmp, 300);
            if (!compare_capture(args, 5, req, "source"))
                retval = getRouteviewBySourceAS(cb, bestonly, atol(tmp));
            else
                retval = getRouteviewByTransitAS(cb, bestonly, atol(tmp));
        } else if (has_capture(args, 8)) {
            extract_capture(args, 10, req, tmp, 300);
            cidr=atoi(tmp);
            extract_capture(args, 8, req, tmp, 300);
            retval = getRouteviewByPrefix(cb, bestonly, tmp, cidr);
        } else if (has_capture(args, 12)) {
			extract_capture(args, 12, req, tmp, 300);
			retval = getRouteviewByOrgName(cb, bestonly, tmp);
		} else if (has_capture(args, 14)) {
			extract_capture(args, 14, req, tmp, 300);
			retval = getRouteviewByNextHop(cb, bestonly, tmp);
		} else if (has_capture(args, 15)) {
			retval = getRouteviewASCount(cb);
		} else if (has_capture(args, 16)) {
			retval = getRouteviewASPrivate(cb, bestonly);
		} else if (has_capture(args, 17)) {
			retval = getRouteviewASReserved(cb, bestonly);
		} else if (has_capture(args, 19)) {
			extract_capture(args, 19, req, tmp, 300);
			retval = getRouteviewNew(cb, bestonly, strtoul(tmp, NULL, 10));
		} else if (has_capture(args, 21)) {
			extract_capture(args, 21, req, tmp, 300);
			retval = getRouteviewPurged(cb, bestonly, strtoul(tmp, NULL, 10));
		} else {
			retval = getRouteviewNew(cb, bestonly, -1);
		}
		decDBReference();
		return retval;
    }
    if(parse_req("^ *netblock +((org-id=\"?([(),\\. A-Za-z0-9_\\-]{3,})\"?)|(source-as=([[:digit:]]{1,10}))) *$", req, args, 30))
    {
		cb->attribute=0;	// command

        //3-org-id, 5-source-as, 7-net-name, 9-net-handle
		if (incDBReferenceAndLock(cb))
			return -1;
		if(has_capture(args,3)) {
			extract_capture(args, 3, req, tmp, 300);
			retval = getNetblockByOrgId(cb, tmp);
		} else if(has_capture(args,5)) {
			extract_capture(args, 5, req, tmp, 300);
			retval = getNetblockBySourceAS(cb, atol(tmp));
		}
		decDBReference();
		return retval;
    }
    if(parse_req("^ *((type=(all)) +)?registry +((org-id=\"?([(),\\. A-Za-z0-9_\\-]{3,})\"?)|(source-as=([[:digit:]]{1,10}))|(org-name=\"?([(),\\. A-Za-z0-9_\\-]{3,})\"?)|(poc-handle=([A-Za-z0-9\\-]{1,20}))|(email=\"?([A-Za-z0-9\\-_.%@]{3,})\"?)) *$", req, args, 30))
    {
		cb->attribute=0;	// command

        //3 - org-id, 5 - source-as, 7 -  org-name, 9 - poc-handle
		int type = 0;
		if (incDBReferenceAndLock(cb))
			return -1;
		if(args[3].rm_so==-1 && args[3].rm_eo==-1)
            type = 0;
        else
            type = 1;
		
        if(has_capture(args,6)) {
            extract_capture(args, 6, req, tmp, 300);
            retval = getRegistryByOrgId(cb, tmp, type);
        } else if(has_capture(args,8)) {
            extract_capture(args, 8, req, tmp, 300);
            retval = getRegistryBySourceAS(cb, atol(tmp), type);
        } else if(has_capture(args,10)) {
            extract_capture(args, 10, req, tmp, 300);
            retval = getRegistryByOrgName(cb, tmp, type);
        } else if(has_capture(args,12)) {
            extract_capture(args, 12, req, tmp, 300);
            retval = getRegistryByPOCHandle(cb, tmp);
        } else if(has_capture(args,14)) {
			if(cb->currentACL->acl<2)
			{
			    writestr(cb, MSG_NOT_AUTHORIZED);
			    return -1;
			}
			extract_capture(args, 14, req, tmp, 300);
			retval = getRegistryByEmail(cb, tmp, type);
		}
		decDBReference();
		return retval;
    }
	if(parse_req("^ *(type=(pwhois|cymru|rpsl|all) +)?((((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))((/([[:digit:]]{1,2}))|(:([[:digit:]]{1,5})))?)( +([A-Za-z0-9.[:space:]_\\-]{1,15}))? *$", req, args, 30))
    {
		cb->attribute=0;	// command

		int disptype,datatype=PW_DATA_NORMAL;
		char extra[20], ipwocidr[20];
        //2 - type, 3 - ipcidr, 4 - ip, 7 - cidr, 9 - port, 11 - extra
		if (incDBReferenceAndLock(cb))
			return -1;
        if(has_capture(args,2))
		{
			extract_capture(args, 2, req, tmp, 300);
			if(!strcmp(tmp,"cymru"))
				disptype=PW_CYMRU;
			else if(!strcmp(tmp,"rpsl"))
					disptype=PW_RPSL;
			else if(!strcmp(tmp,"all")) {
					disptype=PW_PWHOIS;
					datatype=PW_DATA_ALL;
			} else if(!strcmp(tmp,"pwhois")) {
					disptype=PW_PWHOIS;
					datatype=PW_DATA_NORMAL;
			} else {
				disptype=PW_PWHOIS;
				datatype=PW_DATA_NORMAL;
			}
		} else {
			disptype=cb->displayType;
			datatype=cb->dataType;
		}
		if(has_capture(args,7))
			extract_capture(args,3,req,tmp,300);
		else
			extract_capture(args,4,req,tmp,300);
		if(has_capture(args,11))
			extract_capture(args,11,req,extra,20);
		else
			extra[0]=0;
		extract_capture(args,4,req,ipwocidr,20);
		log_printf(3, "getStandardQueryResponse call(ip=%s, ipcidr=%s, extra=%s)\n",ipwocidr,tmp,extra);
		retval = getStandardQueryResponse(cb, disptype, datatype, ipwocidr, tmp, extra);
		log_printf(3, "getStandardQueryResponse is finished\n");
		decDBReference();
		return retval;
    }
	if(echoServerIsEnabled)
	{
		snprintf(tmp,300,"%s\n",req);
		writestr(cb, tmp);
        cb->bulk=1;
		return 0;
	}
	else
		writestr(cb, MSG_INVALIDINPUT);
	return -1;
}

/* EOF */

