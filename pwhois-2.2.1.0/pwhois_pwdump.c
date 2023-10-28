#define _WITH_GETLINE
#include <inttypes.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <regex.h> 
#include <getopt.h>
#include <mysql/mysql.h>
#include "IPV4u.h"

#define DEFAULT_CONFIG "/etc/pwhois/pwhoisd.conf"
#define DEFAULT_ACLDB_EXPORT_FILENAME "/var/pwhois/acl.pwdump"
#define DEFAULT_ASNDB_EXPORT_FILENAME "/var/pwhois/asn.pwdump"
#define DEFAULT_GEODB_EXPORT_FILENAME "/var/pwhois/geo.pwdump"
#define DEFAULT_NETDB_EXPORT_FILENAME "/var/pwhois/net.pwdump"
#define DEFAULT_ORGDB_EXPORT_FILENAME "/var/pwhois/org.pwdump"
#define DEFAULT_POCDB_EXPORT_FILENAME "/var/pwhois/poc.pwdump"
#define DEFAULT_ROUDB_EXPORT_FILENAME "/var/pwhois/rou.pwdump"

#ifndef MAX_PATH
#define MAX_PATH 512
#endif

#define COUNTER_UPDATE 10000

char DB_Server[215];
char DB_Name[215];
char DB_User[215];
char DB_Pass[215];
static char DBConnectionString[1024];
char ACLDB_EXPORT_FILENAME[MAX_PATH];
char ASNDB_EXPORT_FILENAME[MAX_PATH];
char GEODB_EXPORT_FILENAME[MAX_PATH];
char NETDB_EXPORT_FILENAME[MAX_PATH];
char ORGDB_EXPORT_FILENAME[MAX_PATH];
char POCDB_EXPORT_FILENAME[MAX_PATH];
char ROUDB_EXPORT_FILENAME[MAX_PATH];

/* options descriptor */
static struct option longopts[] =
{
	{"loadaclflat",		no_argument,		NULL,			'f'},
	{"loadacl",		no_argument,		NULL,			'a'},
	{"loadasn",		no_argument,		NULL,			's'},
	{"loadgeo",		no_argument,		NULL,			'g'},
	{"loadnet",		no_argument,		NULL,			'n'},
	{"loadorg",		no_argument,		NULL,			'o'},
	{"loadpoc",		no_argument,		NULL,			'p'},
	{"loadroute",	no_argument,		NULL,			't'},
	{"configfile",	required_argument,	NULL,			'c'},
	{NULL,			0,					NULL,			0}
};

struct geo_country_struct_save;
struct geo_region_struct_save;
struct geo_location_struct_save;
struct geo_iprange_struct_save;

typedef struct geo_country_struct_save geo_country_save;
typedef struct geo_region_struct_save geo_region_save;
typedef struct geo_location_struct_save geo_location_save;
typedef struct geo_iprange_struct_save geo_iprange_save;

typedef struct geo_country_struct_save * p_geo_country_save;
typedef struct geo_region_struct_save * p_geo_region_save;
typedef struct geo_location_struct_save * p_geo_location_save;
typedef struct geo_iprange_struct_save * p_geo_iprange_save;

//GEO SQL queries
static char getIPRangesOrderedByIP[]="SELECT ipfrom, ipto FROM ipcitylatlong ORDER BY ipfrom, ipto";
static char getCountries[]="SELECT countryshort, countrylong, COUNT(*) FROM ipcitylatlong GROUP BY countryshort, countrylong ORDER BY countryshort, countrylong";
static char getRegions[]="select ipregion, COUNT(*) FROM ipcitylatlong GROUP BY countryshort, countrylong, ipregion ORDER BY countryshort, countrylong, ipregion";
static char getLocations[]="SELECT ipcity, iplatitude, iplongitude, COUNT(*) FROM ipcitylatlong GROUP BY countryshort, countrylong, ipregion, ipcity, iplatitude, iplongitude ORDER BY countryshort, countrylong, ipregion, ipcity, iplatitude, iplongitude";
static char getIPRangesOrderedByLoc[]="SELECT ipfrom FROM ipcitylatlong ORDER BY countryshort, countrylong, ipregion, ipcity, iplatitude, iplongitude, ipfrom, ipto";

static p_geo_iprange_save allRanges=NULL;
static uint32_t * rangesLocIndex=NULL;
static uint32_t allRngCount=0;

static p_geo_country_save allCountries=NULL;
static uint32_t allCntCount=0;

static p_geo_region_save allRegions=NULL;
static uint32_t allRegCount=0;

static p_geo_location_save allLocations=NULL;
static uint32_t allLocCount=0;

struct geo_country_struct_save
{
	char shortname[3];
	uint32_t c_longname;
	uint32_t regCount;
	uint32_t firstReg;
};
struct geo_region_struct_save
{
	uint32_t p_country;
	uint32_t c_region;
	uint32_t locCount;
	uint32_t firstLoc;
};
struct geo_location_struct_save
{
	uint32_t p_region;
	uint32_t c_city;
	double latitude;
	double longitude;
	uint32_t rngCount;
	uint32_t firstRng;
};
struct geo_iprange_struct_save
{
	uint32_t p_location;
	uint32_t ipfrom;
	uint32_t ipto;
};

#ifdef BIG_ENDIAN
unsigned long long htond(double d)
{
	unsigned long long ret;
	memcpy((void *)&ret, (void *)&d, sizeof(double));
	return ret;
}
#else
unsigned long long htond(double d)
{
	char b[8];
	register char *p = (char *)(&d);
	unsigned long long ret;
	b[7] = *p++;
	b[6] = *p++;
	b[5] = *p++;
	b[4] = *p++;
	b[3] = *p++;
	b[2] = *p++;
	b[1] = *p++;
	b[0] = *p;
	memcpy((void *)&ret, (void *)b, sizeof(double));
	return ret;
}
#endif

static const char * my_get_value(const char * value)
{
    if (value == NULL)
        value = "";
    return value;
}

/* http://burtleburtle.net/bob/hash/evahash.html */
/* The mixing step */
#define mix(a,b,c) \
{ \
  a=a-b;  a=a-c;  a=a^(c>>13); \
  b=b-c;  b=b-a;  b=b^(a<<8);  \
  c=c-a;  c=c-b;  c=c^(b>>13); \
  a=a-b;  a=a-c;  a=a^(c>>12); \
  b=b-c;  b=b-a;  b=b^(a<<16); \
  c=c-a;  c=c-b;  c=c^(b>>5);  \
  a=a-b;  a=a-c;  a=a^(c>>3);  \
  b=b-c;  b=b-a;  b=b^(a<<10); \
  c=c-a;  c=c-b;  c=c^(b>>15); \
}

/* Arguments: key, length of key in bytes, previous hash or arbitrary value */
static uint_fast16_t hashstringto16(register const uint8_t *k, unsigned int length)
{
	register uint32_t	a,b,c;	/* the internal state */
	unsigned int		len;	/* how many key bytes still need mixing */

	/* Set up the internal state */
	len = length;
	a = b = 0x9e3779b9;		/* the golden ratio; an arbitrary value */
	c = 0;					/* variable initialization of internal state */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a=a+(k[0]+((uint32_t)k[1]<<8)+((uint32_t)k[2]<<16) +((uint32_t)k[3]<<24));
		b=b+(k[4]+((uint32_t)k[5]<<8)+((uint32_t)k[6]<<16) +((uint32_t)k[7]<<24));
		c=c+(k[8]+((uint32_t)k[9]<<8)+((uint32_t)k[10]<<16)+((uint32_t)k[11]<<24));
		mix(a,b,c);
		k = k+12; len = len-12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c = c+length;
	switch(len)				/* all the case statements fall through */
	{
	case 11: c=c+((uint32_t)k[10]<<24);
	case 10: c=c+((uint32_t)k[9]<<16);
	case 9 : c=c+((uint32_t)k[8]<<8);
		/* the first byte of c is reserved for the length */
	case 8 : b=b+((uint32_t)k[7]<<24);
	case 7 : b=b+((uint32_t)k[6]<<16);
	case 6 : b=b+((uint32_t)k[5]<<8);
	case 5 : b=b+k[4];
	case 4 : a=a+((uint32_t)k[3]<<24);
	case 3 : a=a+((uint32_t)k[2]<<16);
	case 2 : a=a+((uint32_t)k[1]<<8);
	case 1 : a=a+k[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return (c >> 16) ^ (c & 0xffff);
}

struct string_node {
	uint32_t offset;
	uint32_t len;
	unsigned int next;
};

static char * stringStorage = NULL;
static uint32_t currentStringStorageSize = 0;
static uint32_t stringStorageOffset = 0;
static unsigned int string_ref[2048][65536];
static struct string_node * string_link = NULL;
static unsigned int string_link_num = 0;
static unsigned int string_link_size = 0;

static uint32_t writeStringToStorage(const char *str)
{
	uint32_t curridx = stringStorageOffset;
	unsigned int lidx, bucket, ref, hash, lstr = strlen(str);
	struct string_node *node, *curr, tmp;

	if (curridx + lstr + 1 >= currentStringStorageSize) {
		currentStringStorageSize = (currentStringStorageSize == 0) ? 1048576 : (currentStringStorageSize * 2);
		stringStorage = realloc(stringStorage, currentStringStorageSize);
		if (curridx == 0) {
			string_link_size = 1048576;
			string_link = malloc(string_link_size * sizeof *string_link);
			string_link_num++;	// reserve entry zero
			stringStorage[stringStorageOffset++] = '\0';
			return curridx;
		}
	}
	if (lstr == 0)
		return 0;

	hash = hashstringto16((const uint8_t *)str, lstr);

	lidx = (lstr < 2048 ? lstr : 2048) - 1;
	ref = bucket = string_ref[lidx][hash];
	while (ref != 0) {
		curr = &string_link[ref];
		if (lstr == curr->len && memcmp(str, stringStorage + curr->offset, lstr) == 0)
			goto found;
		ref = curr->next;
	}
	ref = string_link_num++;
	if (ref >= string_link_size) {
		string_link_size *= 2;
		string_link = realloc(string_link, string_link_size * sizeof *string_link);
	}
	curr = &string_link[ref];
	curr->offset = curridx;
	curr->len = lstr;
	curr->next = bucket;
	string_ref[lidx][hash] = ref;
	memcpy(stringStorage + curridx, str, lstr + 1);
	stringStorageOffset += lstr + 1;
	return curridx;

found:
	node = &string_link[bucket];
	tmp = *node;
	*node = *curr;
	*curr = tmp;
	ref = node->next;
	node->next = curr->next;
	curr->next = ref;
	return node->offset;
}

void clearStringStorage()
{
	memset(string_ref, 0, sizeof string_ref);
	free(string_link);
	string_link = NULL;
	string_link_num = 0;
	string_link_size = 0;

	free(stringStorage);
	stringStorage = NULL;
	currentStringStorageSize = 0;
	stringStorageOffset = 0;
}

int saveStringStorage(FILE * outf)
{
	if(fwrite(stringStorage, 1, stringStorageOffset, outf) != stringStorageOffset)
		return -1;
	return 0;
}

void readLine(FILE * f, char * buf, int bfsz)
{
	int i;
	for(i=0;i<bfsz;i++)
	{
		if(fread(buf+i,1,1,f)<1 || buf[i]=='\r' || buf[i]=='\n')
		{
			buf[i]=0;
			break;
		}
	}
}

static void readConfigFile(char * fname)
{
	regex_t re; 
	regex_t comment; 
	regex_t blank; 
	regmatch_t args[10];
	int status;
	FILE * cfgFile;
	char cfgLine[1024], param[512], value[512], tmp;
	
	cfgLine[1023]=0;
	
	status=regcomp(&re, "^ *([A-Za-z0-9_.-]+) *= *\"?([^\"]*)\"? ?$", REG_EXTENDED|REG_ICASE);
	status=regcomp(&comment,"^ *#.*$",REG_EXTENDED|REG_ICASE);
	status=regcomp(&blank,"^ +$",REG_EXTENDED|REG_ICASE);
	cfgFile=fopen(fname,"r");
	if(!cfgFile)
	{
		fprintf(stderr,"Can't open config file %s \n\n",fname);
		exit(EXIT_FAILURE);
	}
	//status=regexec(&re, "db.type=postgres", 10, args, 0);
	DB_Server[0]=0;
	strcpy(DB_Name,"pwhois");
	strcpy(DB_User,"pwhois");
	strcpy(DB_Pass,"pwhois");
	strcpy(ACLDB_EXPORT_FILENAME,DEFAULT_ACLDB_EXPORT_FILENAME);
	strcpy(ASNDB_EXPORT_FILENAME,DEFAULT_ASNDB_EXPORT_FILENAME);
	strcpy(GEODB_EXPORT_FILENAME,DEFAULT_GEODB_EXPORT_FILENAME);
	strcpy(NETDB_EXPORT_FILENAME,DEFAULT_NETDB_EXPORT_FILENAME);
	strcpy(ORGDB_EXPORT_FILENAME,DEFAULT_ORGDB_EXPORT_FILENAME);
	strcpy(POCDB_EXPORT_FILENAME,DEFAULT_POCDB_EXPORT_FILENAME);
	strcpy(ROUDB_EXPORT_FILENAME,DEFAULT_ROUDB_EXPORT_FILENAME);
	while(!feof(cfgFile))
	{
		readLine(cfgFile, cfgLine, 1023);
		if(!strlen(cfgLine) || !regexec(&blank, cfgLine, 10, args, 0) || !regexec(&comment, cfgLine, 10, args, 0))
			continue;
		if((status=regexec(&re, cfgLine, 10, args, 0))!=0)
			continue;
		tmp=cfgLine[args[1].rm_eo];
		cfgLine[args[1].rm_eo]=0;
		strcpy(param,cfgLine+args[1].rm_so);
		cfgLine[args[1].rm_eo]=tmp;
		
		tmp=cfgLine[args[2].rm_eo];
		cfgLine[args[2].rm_eo]=0;
		strcpy(value,cfgLine+args[2].rm_so);
		cfgLine[args[2].rm_eo]=tmp;
		
		if(!strcmp(param,"db.server"))
			strncpy(DB_Server,value,214);
		else if(!strcmp(param,"db.name"))
			strncpy(DB_Name,value,214);
		else if(!strcmp(param,"db.user"))
			strncpy(DB_User,value,214);
		else if(!strcmp(param,"db.password"))
			strncpy(DB_Pass,value,214);
		else if(!strcmp(param,"fastload.acldb"))
			strncpy(ACLDB_EXPORT_FILENAME,value,MAX_PATH);
		else if(!strcmp(param,"fastload.asndb"))
			strncpy(ASNDB_EXPORT_FILENAME,value,MAX_PATH);
		else if(!strcmp(param,"fastload.geodb"))
			strncpy(GEODB_EXPORT_FILENAME,value,MAX_PATH);
		else if(!strcmp(param,"fastload.netdb"))
			strncpy(NETDB_EXPORT_FILENAME,value,MAX_PATH);
		else if(!strcmp(param,"fastload.orgdb"))
			strncpy(ORGDB_EXPORT_FILENAME,value,MAX_PATH);
		else if(!strcmp(param,"fastload.pocdb"))
			strncpy(POCDB_EXPORT_FILENAME,value,MAX_PATH);
		else if(!strcmp(param,"fastload.roudb"))
			strncpy(ROUDB_EXPORT_FILENAME,value,MAX_PATH);
	}
	fclose(cfgFile);
	regfree(&re);
}

size_t rmeol(char *bufp, size_t len)
{
	if (len == 0 || bufp[len - 1] != '\n')
		goto out;
	bufp[--len] = '\0';
	if (len == 0 || bufp[len - 1] != '\r')
		goto out;
	bufp[--len] = '\0';
out:
	return len;
}

size_t skipsep(const char *bufp, size_t pos)
{
	while (bufp[pos] == ',' || bufp[pos] == ' ' || bufp[pos] == '\t')
		pos++;
	return pos;
}

size_t skipfld(char *bufp, size_t pos)
{
	while (bufp[pos] != ',' && bufp[pos] != ' ' && bufp[pos] != '\t') {
		if (bufp[pos] == '#')
			bufp[pos] = '\0';
		if (bufp[pos] == '\0')
			goto out;
		pos++;
	}
	bufp[pos++] = '\0';
out:
	return pos;
}

/* MySQL:  id, ip, cidr, crdt, mddt, status, max_count, comment */
/* Config: ip[/cidr], status, max_count, extra */
int loadACLConfigFile(FILE * inf, FILE * outf)
{
	int ret = 1, lineno = 0;
	ssize_t rlen;
	size_t bufsz = 0, pos, end;
	char *bufp = NULL, *ep, *ptr;
	struct in_addr ipv4;
	long long ipv4num, cidr, status, count;
	uint32_t aclrow[4], nRows = 0;

	if (inf == NULL)
		inf = stdin;

	printf("ACL loading:\n\tReading input from stdin....\n");

	fwrite(&nRows, sizeof nRows, 1, outf);

	while ((rlen = getline(&bufp, &bufsz, inf)) >= 0) {
		lineno++;
		rmeol(bufp, rlen);
		pos = skipsep(bufp, 0);
		if (bufp[pos] == '#' || bufp[pos] == '\0')	/* ignore */
			continue;
		end = skipfld(bufp, pos);	/* parse ip */
		if (pos >= end) {
			fprintf(stderr, "Missing IP on line %d\n", lineno);
			goto fail;
		}
		cidr = 32;
		ptr = strchr(&bufp[pos], '/');
		if (ptr != NULL) {	/* parse cidr */
			*ptr++ = '\0';
			cidr = strtoll(ptr, &ep, 0);
			if (ep == ptr || *ep != '\0' || cidr < 0 || cidr > 32) {
				fprintf(stderr, "Invalid CIDR '%s' on line %d\n", ptr, lineno);
				goto fail;
			}
		}
		ptr = &bufp[pos];
		if (inet_pton(AF_INET, ptr, &ipv4) != 1) {
			ipv4num = strtoll(ptr, &ep, 0);
			if (ep == ptr || *ep != '\0' || ipv4num < 0 || ipv4num >= (1LL << 32)) {
				fprintf(stderr, "Invalid IP: '%s' on line %d\n", ptr, lineno);
				goto fail;
			}
			ipv4.s_addr = htonl(ipv4num);
		}

		pos = skipsep(bufp, end);
		end = skipfld(bufp, pos);	/* parse status */
		if (pos >= end) {
			fprintf(stderr, "Missing status value on line %d\n", lineno);
			goto fail;
		}
		ptr = &bufp[pos];
		status = strtoll(ptr, &ep, 0);
		if (ep == ptr || *ep != '\0' || status < 0 || status > 3) {
			fprintf(stderr, "Invalid status value '%s' on line %d\n", ptr, lineno);
			goto fail;
		}

		pos = skipsep(bufp, end);
		end = skipfld(bufp, pos);	/* parse max_count */
		if (pos >= end) {
			fprintf(stderr, "Missing max_count on line %d\n", lineno);
			goto fail;
		}
		ptr = &bufp[pos];
		count = strtoll(ptr, &ep, 0);
		if (ep == ptr || *ep != '\0' || count < 0 || count > UINT_MAX) {
			fprintf(stderr, "Invalid max_count '%s' on line %d\n", ptr, lineno);
			goto fail;
		}

		aclrow[0] = ipv4.s_addr;
		aclrow[1] = htonl(cidr);
		aclrow[2] = htonl(count);
		aclrow[3] = htonl(status);

		fwrite(aclrow, sizeof aclrow, 1, outf);
		nRows++;
	}

	if (fseek(outf, 0, SEEK_SET) != 0)
		goto fail;
	nRows = htonl(nRows);
	fwrite(&nRows, sizeof nRows, 1, outf);

	if (!feof(inf) || ferror(inf) || ferror(outf))
		goto fail;

	printf("\tTotal: %"PRIu32"\n\n", ntohl(nRows));
	ret = 0;
fail:
	if (bufp != NULL)
		free(bufp);
	return ret;
}

int loadACLDatabase(MYSQL * dbHandle, FILE * outf)
{
	char query[256];
	MYSQL_RES * queryResult;
	MYSQL_ROW myrow;
	uint32_t nRows, i, save32;

	printf("ACL loading:\n\tExecuting request....\n");
	fflush(stdout);
	sprintf(query, "SELECT ip, cidr, max_count, status FROM pwhois_acl WHERE status >= 0");
	if (mysql_query(dbHandle,query))
		return 1;
	queryResult = mysql_store_result(dbHandle);
	if (!queryResult)
		return 1;
	nRows = mysql_num_rows(queryResult);
	save32 = htonl(nRows);
	fwrite(&save32, sizeof(save32), 1, outf);
	printf("\tTotal: %"PRIu32"\n\n", nRows);
	for (i = 0; i < nRows; i++) {
		myrow = mysql_fetch_row(queryResult);
		save32 = htonl(strtoul(myrow[0], NULL, 10));
		fwrite(&save32, sizeof(save32), 1, outf);
		save32 = htonl(strtoul(myrow[1], NULL, 10));
		fwrite(&save32, sizeof(save32), 1, outf);
		save32 = htonl(strtoul(myrow[2], NULL, 10));
		fwrite(&save32, sizeof(save32), 1, outf);
		save32 = htonl(strtoul(myrow[3], NULL, 10));
		fwrite(&save32, sizeof(save32), 1, outf);
	}
	mysql_free_result(queryResult);
	return 0;
}

MYSQL * OpenDatabase(char * dbserver, char * dbname, char * dbUser, char * dbPassword)
{
	MYSQL * dbHandle;
	regex_t ip;
	
	if(strlen(dbserver))
	{
		regcomp(&ip,"^[[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3}$",REG_EXTENDED|REG_ICASE);
		if(!regexec(&ip, dbserver, 0, NULL, 0))
			sprintf(DBConnectionString, "hostaddr=%s ",dbserver);
		else
			sprintf(DBConnectionString, "host=%s ",dbserver);
		regfree(&ip);
	}
	else
		DBConnectionString[0]=0;
	sprintf(DBConnectionString+strlen(DBConnectionString),"dbname = %s user = %s  password = %s\n",dbname, dbUser, dbPassword);
//	dbHandle = PQconnectdb(DBConnectionString);
    dbHandle = mysql_init(NULL);
    if (dbHandle == NULL)
        return NULL;
    dbHandle = mysql_real_connect(dbHandle, NULL, dbUser, dbPassword, dbname, 0, NULL, 0);
	if(dbHandle == NULL)
		return NULL;

	return dbHandle;
}

static void loadAllIPRanges(MYSQL * dbHandle)
{
	uint32_t i;
	MYSQL_RES * queryResult;
    MYSQL_ROW myrow;
	char * stoppoint;
	
	printf("\tLoading IP ranges:\n\tExecuting request....\n");
	if (mysql_query(dbHandle,getIPRangesOrderedByIP))
        return;
    queryResult = mysql_store_result(dbHandle);
	if(!queryResult)
		return;
	
	allRngCount=mysql_num_rows(queryResult);
	printf("\tTotal: %"PRIu32"\n",allRngCount);
	allRanges=malloc(sizeof(geo_iprange_save)*allRngCount);
	if(!allRanges)
	{
		mysql_free_result(queryResult);
		allRngCount=0;
		return;
	}
	for (i = 0; i < allRngCount; i++)
	{
        myrow = mysql_fetch_row(queryResult);
		if(i % allRngCount == COUNTER_UPDATE) printf("\t%"PRIu32"",i+1);
		fflush(stdout);
		allRanges[i].p_location=0;
		allRanges[i].ipfrom=strtoul(myrow[0],&stoppoint,10);
		allRanges[i].ipto=strtoul(myrow[1],&stoppoint,10);
		if(i % allRngCount == COUNTER_UPDATE) printf("\r");
	}
	mysql_free_result(queryResult);
	printf("\n");
}

static void loadAllCountries(MYSQL * dbHandle)
{
	MYSQL_RES * countries;
    MYSQL_ROW myrow;
	uint32_t i, nRows;

	printf("\tLoading countries:\n\tExecuting request....\n");
	if (mysql_query(dbHandle, getCountries))
        return;
    countries = mysql_store_result(dbHandle);
	if(!countries)
		return;
	nRows = mysql_num_rows(countries);
	printf("\tTotal: %"PRIu32"\n",nRows);
	allCountries = malloc( sizeof(geo_country_save) * nRows );
	if(!allCountries)
	{
		mysql_free_result(countries);
		return;
	}
	allCntCount=nRows;
	for(i = 0; i < nRows; i++)
	{
		myrow = mysql_fetch_row(countries);
		if(i % nRows == COUNTER_UPDATE) printf("\t%"PRIu32"",i+1);
		fflush(stdout);
		strncpy(allCountries[i].shortname,myrow[0],2);
		allCountries[i].shortname[2]=0;
		allCountries[i].c_longname=writeStringToStorage(my_get_value(myrow[1]));
		//now we store here number of all ranges but we will change it on regions loading (loadAllRegions)
		allCountries[i].regCount=atol(myrow[2]);
		//we don't know while where is first region in allRegions array. Will be filled in loadAllRegions
		allCountries[i].firstReg=0;
		if(i % nRows == COUNTER_UPDATE) printf("\r");
	}
	mysql_free_result(countries);
	printf("\n");
}

static void loadAllRegions(MYSQL * dbHandle)
{
	MYSQL_RES * regions;
    MYSQL_ROW myrow;
	uint32_t i, nRows, iParent, cntChild, iChild;

	printf("\tLoading regions:\n\tExecuting request....\n");
	if (mysql_query(dbHandle, getRegions))
        return;
    regions = mysql_store_result(dbHandle);
	if(!regions)
		return;
	nRows = mysql_num_rows(regions);
	printf("\tTotal: %"PRIu32"\n",nRows);
	allRegions = malloc( sizeof(geo_region_save) * nRows );
	if(!allRegions)
	{
		mysql_free_result(regions);
		return;
	}
	allRegCount=nRows;
	for(iParent=0, i=0; iParent<allCntCount; iParent++)
	{
		cntChild=allCountries[iParent].regCount;
		allCountries[iParent].firstReg=i;
		for(iChild=0, allCountries[iParent].regCount=0; iChild<cntChild; i++, allCountries[iParent].regCount++, iChild+=allRegions[i-1].locCount)
		{
			myrow = mysql_fetch_row(regions);
			if(i % nRows == COUNTER_UPDATE) printf("\t%"PRIu32"",i+1);
			fflush(stdout);
			allRegions[i].p_country=iParent;
			allRegions[i].c_region=writeStringToStorage(my_get_value(myrow[0]));
			//now we store here number of all ranges but we will change it on locations loading (loadAllLocations)
			allRegions[i].locCount=atol(myrow[1]);
			//we don't know now where is first location in allLocations array. Will be filled in loadAllLocations
			allRegions[i].firstLoc=0;
			if(i % nRows == COUNTER_UPDATE) printf("\r");
		}
	}
	mysql_free_result(regions);
	printf("\n");
}

static void loadAllLocations(MYSQL * dbHandle)
{
	MYSQL_RES * locations;
    MYSQL_ROW myrow;
	uint32_t i, nRows, iParent, cntChild, iChild;
	
	printf("\tLoading locations:\n\tExecuting request....\n");
	if (mysql_query(dbHandle, getLocations))
		return;
	locations = mysql_store_result(dbHandle);
	if(!locations)
		return;
	nRows = mysql_num_rows(locations);
	printf("\tTotal: %"PRIu32"\n",nRows);
	allLocations = malloc( sizeof(geo_location_save) * nRows );
	if(!allLocations)
	{
		mysql_free_result(locations);
		return;
	}
	allLocCount=nRows;
	for(iParent=0, i=0; iParent<allRegCount; iParent++)
	{
		cntChild=allRegions[iParent].locCount;
		allRegions[iParent].firstLoc=i;
		for(iChild=0, allRegions[iParent].locCount=0; iChild<cntChild; i++, allRegions[iParent].locCount++, iChild+=allLocations[i-1].rngCount)
		{
			myrow = mysql_fetch_row(locations);
			if(i % nRows == COUNTER_UPDATE) printf("\t%"PRIu32"",i+1);
			fflush(stdout);
			allLocations[i].p_region=iParent;
			allLocations[i].c_city=writeStringToStorage(my_get_value(myrow[0]));
			allLocations[i].latitude=atof(myrow[1]);
			allLocations[i].longitude=atof(myrow[2]);
			allLocations[i].rngCount=atol(myrow[3]);
			//we don't know now where is first location in rangesLocIndex array. Will be filled in loadRangesLocIndex
			allLocations[i].firstRng=0;
			if(i % nRows == COUNTER_UPDATE) printf("\r");
		}
	}
	mysql_free_result(locations);
	printf("\n");
}

static uint32_t internalFindIPRange(uint32_t from, uint32_t step, uint32_t ip)
{
	if(from+step>=allRngCount)
		step=allRngCount-from;
	while(allRanges[from+step-1].ipto<ip)
	{
		from+=step;
		if(from+step>=allRngCount)
			step=allRngCount-from;
	}
	return from;
}

uint32_t FindIPRange(uint32_t ip)
{
    uint32_t resultidx;
    if(!allRngCount)
        return 0xFFFFFFFF;
    resultidx=internalFindIPRange(0, 1000000, ip);
    resultidx=internalFindIPRange(resultidx, 10000, ip);
    resultidx=internalFindIPRange(resultidx, 100, ip);
    resultidx=internalFindIPRange(resultidx, 1, ip);
    if(allRanges[resultidx].ipfrom > ip)
        return 0xFFFFFFFF;
    return resultidx;
}

static void loadRangesLocIndex(MYSQL * dbHandle)
{
	MYSQL_RES * ranges;
    MYSQL_ROW myrow;
	uint32_t i, nRows, iParent, cntChild, iChild, ipfrom;
	char * stoppoint;
	
	printf("\tLoading location-range links:\n\tExecuting request....\n");
	if (mysql_query(dbHandle, getIPRangesOrderedByLoc))
        return;
    ranges = mysql_store_result(dbHandle);
	if(!ranges)
		return;
	nRows = mysql_num_rows(ranges);
	printf("\tTotal: %"PRIu32"\n",nRows);
	rangesLocIndex = malloc( sizeof(uint32_t) * nRows );
	if(!rangesLocIndex)
	{
		mysql_free_result(ranges);
		return;
	}
	//we don't need change it because we did it in LoadAllIPRanges
	//allRngCount=cnt;
	for(iParent=0, i=0; iParent<allLocCount; iParent++)
	{
		cntChild=allLocations[iParent].rngCount;
		allLocations[iParent].firstRng=i;
		for(iChild=0, allLocations[iParent].rngCount=0; iChild<cntChild; i++, allLocations[iParent].rngCount++, iChild++)
		{
            myrow = mysql_fetch_row(ranges);
			if(i % nRows == COUNTER_UPDATE) printf("\t%"PRIu32"",i+1);
			fflush(stdout);
			ipfrom=strtoul(myrow[0],&stoppoint,10);
			rangesLocIndex[i]=FindIPRange(ipfrom);
			allRanges[rangesLocIndex[i]].p_location=iParent;
			if(i % nRows == COUNTER_UPDATE) printf("\r");
		}
	}
	mysql_free_result(ranges);
	printf("\n");
}

int LoadGeoData(MYSQL * dbHandle, FILE * outf)
{
	uint32_t i, ulforsave;
	unsigned long long dforsave;
	clearStringStorage();
	writeStringToStorage("");
	printf("GEO loading:\n");
	loadAllIPRanges(dbHandle);
	if(!allRanges)
		return 1;
	
	loadAllCountries(dbHandle);
	if(!allCountries)
	{
		free(allRanges);
		return 1;
	}
	
	loadAllRegions(dbHandle);
	if(!allRegions)
	{
		free(allRanges);
		free(allCountries);
		return 1;
	}
	
	loadAllLocations(dbHandle);
	if(!allLocations)
	{
		free(allRanges);
		free(allCountries);
		free(allRegions);
		return 1;
	}
	
	loadRangesLocIndex(dbHandle);
	if(!rangesLocIndex)
	{
		free(allRanges);
		free(allCountries);
		free(allRegions);
		free(allLocations);
		return 1;
	}
	ulforsave=htonl(allCntCount);
	fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
	ulforsave=htonl(allRegCount);
	fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
	ulforsave=htonl(allLocCount);
	fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
	ulforsave=htonl(allRngCount);
	fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
	printf("\n\tSaving countries...\n");
	for(i=0;i<allCntCount;i++)
	{
		if(i % allCntCount == COUNTER_UPDATE) printf("\t%"PRIu32"",i+1);
		fflush(stdout);
		fwrite(allCountries[i].shortname, 1, 3, outf);
		ulforsave=htonl(allCountries[i].c_longname);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		ulforsave=htonl(allCountries[i].regCount);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		ulforsave=htonl(allCountries[i].firstReg);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		if(i % allCntCount == COUNTER_UPDATE) printf("\r");
	}
	printf("\n\tSaving regions...\n");
	for(i=0;i<allRegCount;i++)
	{
		if(i % allRegCount == COUNTER_UPDATE) printf("\t%"PRIu32"",i+1);
		fflush(stdout);
		ulforsave=htonl(allRegions[i].p_country);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		ulforsave=htonl(allRegions[i].c_region);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		ulforsave=htonl(allRegions[i].locCount);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		ulforsave=htonl(allRegions[i].firstLoc);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		if(i % allRegCount == COUNTER_UPDATE) printf("\r");
	}
	printf("\n\tSaving locations...\n");
	for(i=0;i<allLocCount;i++)
	{
		if(i % allLocCount == COUNTER_UPDATE) printf("\t%"PRIu32"",i+1);
		fflush(stdout);
		ulforsave=htonl(allLocations[i].p_region);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		ulforsave=htonl(allLocations[i].c_city);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		dforsave=htond(allLocations[i].latitude);
		fwrite(&dforsave, sizeof(unsigned long long), 1, outf);
		dforsave=htond(allLocations[i].longitude);
		fwrite(&dforsave, sizeof(unsigned long long), 1, outf);
		ulforsave=htonl(allLocations[i].rngCount);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		ulforsave=htonl(allLocations[i].firstRng);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		if(i % allLocCount == COUNTER_UPDATE)  printf("\r");
	}
	printf("\n\tSaving ranges...\n");
	for(i=0;i<allRngCount;i++)
	{
		if(i % allRngCount == COUNTER_UPDATE)  printf("\t%"PRIu32"",i+1);
		fflush(stdout);
		ulforsave=htonl(allRanges[i].p_location);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		ulforsave=htonl(allRanges[i].ipfrom);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		ulforsave=htonl(allRanges[i].ipto);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		if(i % allRngCount == COUNTER_UPDATE) printf("\r");
	}
	printf("\n\tSaving range-location links...\n");
	for(i=0;i<allRngCount;i++)
	{
		if(i % allRngCount == COUNTER_UPDATE) printf("\t%"PRIu32"",i+1);
		fflush(stdout);
		ulforsave=htonl(rangesLocIndex[i]);
		fwrite(&ulforsave, sizeof(uint32_t), 1, outf);
		if(i % allRngCount == COUNTER_UPDATE) printf("\r");
	}
	printf("\n\tSaving strings...");
	saveStringStorage(outf);
	clearStringStorage();
	printf("\n");
	free(allRanges);
	free(allCountries);
	free(allRegions);
	free(allLocations);
	free(rangesLocIndex);
	return 0;
}

static void my_save_values(const MYSQL_ROW myrow, uint32_t *row32, unsigned int index, unsigned int num_values)
{
	for (num_values += index; index < num_values; index++)
		row32[index] = htonl(strtoul(my_get_value(myrow[index]), NULL, 10));
}

static void my_save_strings(const MYSQL_ROW myrow, uint32_t *row32, unsigned int index, unsigned int num_strings)
{
	for (num_strings += index; index < num_strings; index++)
		row32[index] = htonl(writeStringToStorage(my_get_value(myrow[index])));
}

static int my_query_save(char * loading, FILE * outf, uint32_t * pnRows, unsigned int nValues, unsigned int nStrings, MYSQL * dbHandle, char * query)
{
	uint32_t nRows, nCols = nValues + nStrings, *row32 = malloc(nCols * sizeof *row32);
	MYSQL_RES * queryResult;
	MYSQL_ROW myrow;

	printf("%s loading:\n\tExecuting request....\n", loading);
	nRows = 0;
	if (mysql_query(dbHandle, query))
		return 1;
	queryResult = mysql_use_result(dbHandle);
	if (!queryResult)
		return 1;
	printf("Fetching records....\n");
	while ((myrow = mysql_fetch_row(queryResult)) != NULL) {
		if (nRows % COUNTER_UPDATE == 0) {
			printf("\r\t%"PRIu32, nRows);
			fflush(stdout);
		}
		nRows++;
		my_save_values(myrow, row32, 0, nValues);
		my_save_strings(myrow, row32, nValues, nStrings);
		fwrite(row32, 1, nCols * sizeof *row32, outf);
	}
	printf("\r\tGot %"PRIu32" records\n", nRows);
	mysql_free_result(queryResult);
	free(row32);
	*pnRows = nRows;
	return 0;
}

static int my_db_save(char * loading, FILE * outf, unsigned int nValues, unsigned int nStrings, MYSQL * dbHandle, char * query)
{
	uint32_t nRows;

	nRows = 0;
	fwrite(&nRows, sizeof(nRows), 1, outf);	// placeholder
	clearStringStorage();
	writeStringToStorage("");
	if (my_query_save(loading, outf, &nRows, nValues, nStrings, dbHandle, query))
		return 1;
	printf("\tSaving strings....\n\n");
	saveStringStorage(outf);
	fseek(outf, 0, SEEK_SET);
	nRows = htonl(nRows);
	fwrite(&nRows, sizeof(nRows), 1, outf);
	clearStringStorage();
	return 0;
}

int loadASNDatabase(MYSQL * dbHandle, FILE * outf)
{
	return my_db_save("ASN", outf, 4, 10, dbHandle, "SELECT asn, source, createdate, modifydate, ashandle, org_id, asname, registerdate, updatedate, adminhandle, techhandle, as_orgname, comment, mailbox FROM asn");
}

int loadNetDatabase(MYSQL * dbHandle, FILE * outf)
{
	return my_db_save("Net", outf, 7, 10, dbHandle, "SELECT network, enetrange, createdate, modifydate, nettype, source, status, netname, registerdate, updatedate, nochandle, abusehandle, techhandle, org_id, nethandle, orgname, mailbox FROM netblock ORDER BY network ASC, enetrange DESC, registerdate ASC");
}

int loadOrgDatabase(MYSQL * dbHandle, FILE * outf)
{
	return my_db_save("Org", outf, 5, 20, dbHandle, "SELECT id, canallocate, source, createdate, modifydate, org_id, orgname, street1, street2, street3, street4, street5, street6, city, state, country, postalcode, registerdate, updatedate, adminhandle, nochandle, abusehandle, techhandle, referralserver, comment FROM organization");
}

int loadPOCDatabase(MYSQL * dbHandle, FILE * outf)
{
	return my_db_save("POC", outf, 4, 20, dbHandle, "SELECT isrole, source, createdate, modifydate, registerdate, updatedate, pochandle, firstname, middlename, lastname, rolename, street1, street2, street3, street4, street5, street6, city, state, country, postalcode, officephone, mailbox, comment FROM poc");
}

int loadRoutesDatabase(MYSQL * dbHandle, FILE * outf)
{
	char query[256], org_id[64];
	uint32_t nRows[2][2], nASNs, nPeers, i, save32, country, row32[8];
	MYSQL_RES * queryResult, * queryResult2;
	MYSQL_ROW myrow;
	uint32_t nullstring = 0, network;
	uint_fast8_t octet;
	uint8_t cidr;
	unsigned int status, best_route;

	printf("ROUTES loading:\n");//write out 4 dummy placeholder values for now
	for (status = 0; status <= 1; status++)
		for (best_route = 0; best_route <= 1; best_route++) {
			nRows[best_route][status] = 0;
			fwrite(&nRows[best_route][status], sizeof(save32), 1, outf);
		}
	sprintf(query, "BEGIN");
	if (mysql_query(dbHandle, query))
		return 1;
	sprintf(query, "SELECT next_hop FROM bgp_routes WHERE best_route=1 AND status=1 GROUP BY next_hop ORDER BY next_hop ASC");
	printf("\tPeers:\n\tExecuting request....\n");
	if (mysql_query(dbHandle, query))
		return 1;
	queryResult = mysql_store_result(dbHandle);
	if (!queryResult)
		return 1;
	nPeers = mysql_num_rows(queryResult);
	printf("\tTotal: %"PRIu32"\n",nPeers);
	save32 = htonl(nPeers);
	fwrite(&save32, sizeof(save32), 1, outf);
	for (i = 0; i < nPeers; i++) {
		myrow = mysql_fetch_row(queryResult);
		save32 = htonl(strtoul(my_get_value(myrow[0]), NULL, 10));
		fwrite(&save32, sizeof(save32), 1, outf);
	}
	mysql_free_result(queryResult);

	clearStringStorage();
	writeStringToStorage("");
	sprintf(query, "SELECT COUNT(*), bgp_routes.asn, as_orgname, org_id FROM bgp_routes LEFT JOIN asn ON bgp_routes.asn=asn.asn WHERE best_route=1 and status=1 GROUP BY asn ORDER BY COUNT(*) DESC, asn");
	printf("\tASN count:\n\tExecuting request....\n");
	if (mysql_query(dbHandle, query))
		return 1;
	queryResult = mysql_store_result(dbHandle);
	if (!queryResult)
		return 1;
	nASNs = mysql_num_rows(queryResult);
	printf("\tTotal: %"PRIu32"\n",nASNs);
	save32 = htonl(nASNs);
	fwrite(&save32, sizeof(save32), 1, outf);
	for (i = 0; i < nASNs; i++) {
		myrow = mysql_fetch_row(queryResult);
		my_save_values(myrow, row32, 0, 2);
		if (myrow[3] == NULL)
			org_id[0] = '\0';
		else
			mysql_real_escape_string(dbHandle, org_id, myrow[3], strlen(myrow[3]));
		country = nullstring;
		if (myrow[2] != NULL && myrow[2][0] != '\0') {
			save32 = htonl(writeStringToStorage(myrow[2]));
			if (org_id[0] != '\0') {
				sprintf(query, "SELECT country FROM organization WHERE org_id='%s' LIMIT 1", org_id);
				if (mysql_query(dbHandle, query))
					return 1;
				queryResult2 = mysql_store_result(dbHandle);
				if (!queryResult2)
					return 1;
				if (mysql_num_rows(queryResult2) > 0) {
					myrow = mysql_fetch_row(queryResult2);
					country = htonl(writeStringToStorage(my_get_value(myrow[0])));
				}
				mysql_free_result(queryResult2);
			}
		} else {
			if (org_id[0] == '\0')
				save32 = nullstring;	// Absent org_id or missing record in asn table
			else {
				sprintf(query, "SELECT orgname, country FROM organization WHERE org_id='%s' LIMIT 1", org_id);
				if (mysql_query(dbHandle, query))
					return 1;
				queryResult2 = mysql_store_result(dbHandle);
				if (!queryResult2)
					return 1;
				if (mysql_num_rows(queryResult2) == 0)
					save32 = nullstring;	// Missing org record
				else {
					myrow = mysql_fetch_row(queryResult2);
					save32 = htonl(writeStringToStorage(my_get_value(myrow[0])));
					country = htonl(writeStringToStorage(my_get_value(myrow[1])));
				}
				mysql_free_result(queryResult2);
			}
		}
		row32[2] = country;
		row32[3] = save32;
		fwrite(row32, 1, 4 * sizeof *row32, outf);
	}
	mysql_free_result(queryResult);

	for (status = 0; status <= 1; status++)
		for (best_route = 0; best_route <= 1; best_route++) {
			printf("Executing routes query %d of 4 (this will take a while)....\n", status * 2 + best_route + 1);
			sprintf(query, "SELECT asn_paths, createdate, modifydate, router_id, asn, next_hop, network, cidr FROM bgp_routes WHERE best_route=%d AND status=%d ORDER BY network DESC, cidr DESC, next_hop DESC", best_route, status);
			if (mysql_query(dbHandle, query))
				return 1;
			queryResult = mysql_use_result(dbHandle);
			if (!queryResult)
				return 1;
			printf("Fetching records....\n");
			while ((myrow = mysql_fetch_row(queryResult)) != NULL) {
				if(nRows[best_route][status] % COUNTER_UPDATE == 0) {
					printf("\r\t%"PRIu32, nRows[best_route][status]);
					fflush(stdout);
				}
				nRows[best_route][status]++;
				my_save_strings(myrow, row32, 0, 1);
				my_save_values(myrow, row32, 1, 5);
				network = strtoul(my_get_value(myrow[6]), NULL, 10);
				if (myrow[7] == NULL) {
					octet = network >> 24;
					if (octet <= 127)
						cidr = 8;
					else
						if (octet <= 191)
							cidr = 16;
						else
							cidr = 24;
				} else
					cidr = strtoul(myrow[7], NULL, 10);
				row32[6] = htonl(network);
				row32[7] = htonl(cidr);
				fwrite(row32, 1, sizeof row32, outf);
			}
			printf("\r\tGot %"PRIu32" records\n", nRows[best_route][status]);
			mysql_free_result(queryResult);
		}
	sprintf(query, "COMMIT");
	if (mysql_query(dbHandle, query))
		return 1;
	printf("\n\tSaving strings....\n\n");
	saveStringStorage(outf);
	fseek(outf, 0, SEEK_SET);
	for (status = 0; status <= 1; status++)
		for (best_route = 0; best_route <= 1; best_route++) {
			save32 = htonl(nRows[best_route][status]);
			fwrite(&save32, sizeof(save32), 1, outf);
		}
	clearStringStorage();
	return 0;
}

void usage()
{
	printf("usage: preppwdump [*options*]\n\n"
		   "  -h, --help           display this help and exit\n"
		   "  -c, --configfile f   read startup settings from pwhoisd configuration file: default is %s \n"
		   "  -a, --loadacl        prepare ACL data dump \n"
		   "  -f, --loadaclflat    prepare ACL data dump from flat input\n"
		   "  -s, --loadasn        prepare ASN data dump \n"
		   "  -g, --loadgeo        prepare GEO data dump \n"
		   "  -n, --loadnet        prepare NET data dump \n"
		   "  -o, --loadorg        prepare ORG data dump \n"
		   "  -p, --loadpoc        prepare POC data dump \n"
		   "  -t, --loadrout       prepare ROUTE data dump \n",
		   DEFAULT_CONFIG);
	
	exit(EXIT_FAILURE);
}

FILE * load_prep(const char * exppath, const char * expfname)
{
	char fname[MAX_PATH];
	FILE * outf = NULL;

	snprintf(fname, MAX_PATH, "%s%s.tmp", exppath, expfname);
	outf = fopen(fname, "wb");
	if (!outf)
		printf("Cant open export file %s\n", fname);
	return outf;
}

int load_db(const char * exppath, const char * expfname, MYSQL * dbHandle, int (*loader)(MYSQL *, FILE *))
{
	int ret = 1;
	FILE * outf = NULL;

	outf = load_prep(exppath, expfname);
	if (!outf || loader(dbHandle, outf))
		goto fail;

	ret = 0;
fail:
	if (outf)
		fclose(outf);
	return ret;
}

int main (int argc, char * argv[])
{
	char cfgpath[MAX_PATH];
	char exppath[MAX_PATH];
	int ret = EXIT_FAILURE, ch, wantdb = 1, loadaclflat = 0, loadacl=0, loadgeo=0, loadnet=0, loadorg=0, loadpoc=0, loadasn=0, loadroute=0;
	strncpy(cfgpath,DEFAULT_CONFIG,MAX_PATH);
	exppath[0]=0;
	MYSQL * dbHandle=NULL;
	FILE * outf = NULL;

	while((ch = getopt_long(argc, argv, "afgnopstc:", longopts, NULL)) != -1)
	{
		switch(ch)
		{
			case 'a':
				loadacl=1;
				break;
			case 'f':
				loadaclflat=1;
				break;
			case 'g':
				loadgeo=1;
				break;
			case 'n':
				loadnet=1;
				break;
			case 'o':
				loadorg=1;
				break;
			case 'p':
				loadpoc=1;
				break;
			case 's':
				loadasn=1;
				break;
			case 't':
				loadroute=1;
				break;
			case 'c':
				strncpy(cfgpath, optarg, MAX_PATH);
				break;
			default:
				usage();
				break;
		}
	}
	if(!loadacl && !loadgeo && !loadnet && !loadorg && !loadpoc && !loadasn && !loadroute)
		wantdb = 0;
	if(!wantdb && !loadaclflat)
	{
		printf("Specify parts for export: a - ACL, f - flat ACL, s - ASN, g - GEO, n - NET, o - ORG, p - POC, t - ROUTE\n");
		usage();
		return EXIT_FAILURE;
	}
	readConfigFile(cfgpath);
	if (loadaclflat) {
		outf = load_prep(exppath, ACLDB_EXPORT_FILENAME);
		if (!outf || loadACLConfigFile(NULL, outf))
			goto err;
	}
	if (!wantdb)
		goto success;
	dbHandle=OpenDatabase(DB_Server, DB_Name, DB_User, DB_Pass);
	if(!dbHandle)
		goto err;

	if(loadacl && load_db(exppath, ACLDB_EXPORT_FILENAME, dbHandle, &loadACLDatabase))
		goto err;

	if(loadasn && load_db(exppath, ASNDB_EXPORT_FILENAME, dbHandle, &loadASNDatabase))
		goto err;

	if(loadgeo && load_db(exppath, GEODB_EXPORT_FILENAME, dbHandle, &LoadGeoData))
		goto err;

	if(loadnet && load_db(exppath, NETDB_EXPORT_FILENAME, dbHandle, &loadNetDatabase))
		goto err;

	if(loadorg && load_db(exppath, ORGDB_EXPORT_FILENAME, dbHandle, &loadOrgDatabase))
		goto err;

	if(loadpoc && load_db(exppath, POCDB_EXPORT_FILENAME, dbHandle, &loadPOCDatabase))
		goto err;

	if(loadroute && load_db(exppath, ROUDB_EXPORT_FILENAME, dbHandle, &loadRoutesDatabase))
		goto err;

success:
	ret = EXIT_SUCCESS;
err:
	if(dbHandle)
		mysql_close(dbHandle);
	if(outf)
		fclose(outf);
	return ret;
}

