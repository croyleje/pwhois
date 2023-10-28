/*
 *  pwhois_thread.h
 *  
 *	Copyright 2007-13 VOSTROM Holdings, Inc.  
 *  This file is part of the Distribution.  See the file COPYING for details.
 */
#ifndef PWHOIS_THREAD_H
#define PWHOIS_THREAD_H

#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include "geounit.h"
#include "patricia.h"

#define PW_PWHOIS	0
#define PW_CYMRU	1
#define PW_RPSL		2

#define PW_DATA_UNKNOWN	0
#define PW_DATA_NORMAL	1
#define PW_DATA_ALL		2

#define NETWORK_CLASS_UNKNOWN 0
#define NETWORK_CLASS_BGP 1
#define NETWORK_CLASS_OSPF 2
#define NETWORK_CLASS_ALL 127
// add more here 


#define DEFAULT_MAX_QUERIES 5000

//Counter index constants
#define CNTR_MIN            0

#define CNTR_UNIQUE_PEERS   0

#define CNTR_QUERY_PWHOIS   1

#define CNTR_QUERY_RVIEW_PX 2
#define CNTR_QUERY_RVIEW_AS 3
#define CNTR_QUERY_RVIEW_ON 4
#define CNTR_QUERY_RVIEW_NH 5
#define CNTR_QUERY_RVIEW_AC 6
#define CNTR_QUERY_RVIEW_AP 7
#define CNTR_QUERY_RVIEW_AR 8
#define CNTR_QUERY_RVIEW_N  9
#define CNTR_QUERY_RVIEW_P  10
#define CNTR_QUERY_RVIEW_TAS 11

#define CNTR_QUERY_NBLCK_AS 12
#define CNTR_QUERY_NBLCK_OI 13

#define CNTR_QUERY_REGTR_OI 14
#define CNTR_QUERY_REGTR_ON 15
#define CNTR_QUERY_REGTR_AS 16
#define CNTR_QUERY_REGTR_PH 17
#define CNTR_QUERY_REGTR_EM 18

#define CNTR_QUERY_PEERS    19

#define CNTR_QUERY_MILTER   20
#define CNTR_QUERY_MSIO		21
#define CNTR_QUERY_FAIL2BAN 22

#define CNTR_ACTIVE_CONN    23

#define CNTR_FIRST_UNUSED   24

#define CNTR_MAX            23

#define WHOIS_SOURCE_UNKNOWN	0
#define WHOIS_SOURCE_ARIN		1
#define WHOIS_SOURCE_RIPE		2
#define WHOIS_SOURCE_APNIC		3
#define WHOIS_SOURCE_JPNIC		4
#define WHOIS_SOURCE_AFRINIC	5
#define WHOIS_SOURCE_LACNIC		6
#define WHOIS_SOURCE_TWNIC		7
#define WHOIS_SOURCE_KRNIC		8
#define WHOIS_SOURCE_IRINN		9
#define WHOIS_SOURCE_JPIRR		10

#define WHOIS_SOURCE_MAX		10

struct WHOIS_SOURCE_TYPE {
	int source;
	char * name;
};

#define ATOLOWER	0x20
#define ATOUPPER	~(ATOLOWER)

#define CASE_SENSITIVE		0
#define CASE_INSENSITIVE	ATOLOWER

typedef struct  _pwhois_thread_ctr_block
{
	pthread_t tid;
	int busy;
	long reqcount;
	int sock;
	int bulk;
	int attribute;			/* indicates that user passed misc. attribute data, not a command */
	int bulkCount;
	char application[256];
	int displayType;
	int dataType;
	char peerIp[256];
	char localIp[256];
	int localPort;
    time_t lastRegTime;
    struct ip * currentACL;
	//for readline
	int rl_cnt;
	char * rl_bufptr;
	char rl_buf[40000];
} pwhois_thread_cb;

struct route
{
    char * asnPaths;
    time_t createDate;
    time_t modifyDate;
    uint32_t routerID;
    uint32_t asn;
    uint32_t next_hop;
	uint32_t prefix;
	uint8_t cidr;
	uint8_t best_route;
	uint8_t status;
};

struct route_list {
	unsigned int num;
	unsigned int size;
	struct route * route[0];
};

struct routes {
	struct route_list * routes[2][2];
};

struct asn {
	uint32_t asn;
	int source;
	time_t createDate;
	time_t modifyDate;
	char * asHandle;
	char * org_id;
	char * asName;
	char * registerDate;
	char * updateDate;
	char * adminHandle;
	char * techHandle;
	char * asOrgName;
	char * comment;
	char * mailbox;
};

struct asn_ll {
	struct asn_ll * next;
	struct asn * as;
	struct route_list * list;
    struct route_list * transit_list;
	uint32_t asn;
};

struct asn_count {
	uint32_t count;
	uint32_t asn;
	char * country;
	char * orgName;
};

struct netblock {
	uint32_t network;
	uint32_t enetrange;
	time_t createDate;
	time_t modifyDate;
	int netType;
	int source;
	int status;
	char * netName;
	char * registerDate;
	char * updateDate;
	char * nocHandle;
	char * abuseHandle;
	char * techHandle;
	char * org_id;
	char * netHandle;
	char * orgName;
	char * mailbox;
};

struct net_list {
	unsigned int num;
	unsigned int size;
	struct netblock * net[0];
};

struct org {
	int id;
	int canAllocate;
	int source;
	time_t createDate;
	time_t modifyDate;
	char * org_id;
	char * orgName;
	char * street[6];
	char * city;
	char * state;
	char * country;
	char * postalCode;
	char * registerDate;
	char * updateDate;
	char * adminHandle;
	char * nocHandle;
	char * abuseHandle;
	char * techHandle;
	char * referralServer;
	char * comment;
};

struct org_list {
	unsigned int num;
	unsigned int size;
	struct org * org[0];
};

struct poc_ll;

struct poc {
	int isrole;
	int source;
	uint32_t createDate, modifyDate;
	char * registerDate, * updateDate;
	char * pocHandle;
	char * firstName, * middleName, * lastName;
	char * roleName;
	char * street[6];
	char * city, * state, * country, * postalCode;
	char * officePhone;
	char * mailbox;
	char * comment;
	struct poc_ll * poc;	// This is here since an index scan is slower
};

struct poc_ll {
	struct poc_ll * next;
	struct poc * poc;
	struct org_list * orglist;
	char * pocHandle;
};

struct ip
{
    unsigned char ip[4];
	unsigned int cidr;
	int count;
	time_t lastQuery;
	time_t lastReset;
	time_t firstQuery;
	int limit;
	int acl;
};

void EnableEchoServer();
typedef int (* process_ip)(struct ip *, void *);
size_t process_all_requests(int * error, process_ip func, void * cookie);
//getting and storage of some runtime parameters
int getQueriesLimit();
int setQueriesLimit(int limit);
time_t getCacheDate();
void save_listen_port(int port);
//counters functions
unsigned long incCounter(int idx);
unsigned long getCounter(int idx);
unsigned long decCounter(int idx);
//in-memory database of clients
struct ip * get_acl_for_ip(int * isnew, char * ipstr, unsigned int cidr);
//main functions of pwhois
void loadACL_fromFile(char * fname);
int handleWhoisRequest(char * ipcidr, char * network, uint32_t * asn, char * asnPaths, time_t * tcrdt, time_t * tmddt, uint32_t * next_hop, char * as_orgName, uint32_t* as_orgNameSrc, char * orgName, uint32_t* orgNameSrc, char * netName, uint32_t* netNameSrc, p_geo_iprange * geo, struct org_list ** orglist, unsigned int * opos, struct netblock ** netblk, struct asn ** as);
void getVersionRuntime(char * response, int sz);
void getPeerIP(uint32_t idx, char * buf);
//init threads
pwhois_thread_cb * initialize_threads(int listenfd, int addrlen, int count);
void databaseReload(int ts);
void SetupFilterParameters(int use_filt, uint32_t filt_router_id);
void ACL_Reload_fromFile(int ts);

int inc_loading_step(char * name, unsigned long sz);
unsigned long inc_loading_step_counter();

int parse_and_execute(char * req, pwhois_thread_cb * cb);
int _getRegistryByPOCHandleShort(char * presponse, const char * pocHandle, const char * handleName, int type);

#endif


/* EOF */

