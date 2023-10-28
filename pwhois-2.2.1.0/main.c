/*
 *  main.c
 *
 *	Copyright 2007-13 VOSTROM Holdings, Inc.  
 *  This file is part of the Distribution.  See the file COPYING for details.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include <sys/param.h>   /* for NONFILE */
#include <sys/stat.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <netdb.h>
#include <regex.h>
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <unistd.h>

#include "geounit.h"
#include "tst_malloc.h"
#include "logger.h"
#include "pwhois_thread.h"

#ifdef SIGTSTP /* if System is BSD*/
#include<sys/file.h>
#include<sys/ioctl.h>
#endif

#define DEFAULT_CONFIG "/etc/pwhois/pwhoisd.conf"
#define DEFAULT_PIDFILE "/var/run/pwhoisd.pid"
#define DEFAULT_LOGFILE "/var/log/pwhoisd.log"
#define DEFAULT_WHOIS_PORT 43
#define DEFAULT_UID 65334
#define DEFAULT_GID 65334

#ifndef MAX_PATH
#define MAX_PATH 512
#endif

#define DEFAULT_ACLDB_EXPORT_FILENAME "/var/pwhois/ACLDB.pwdump"
#define DEFAULT_ASNDB_EXPORT_FILENAME "/var/pwhois/ASNDB.pwdump"
#define DEFAULT_GEODB_EXPORT_FILENAME "/var/pwhois/GEODB.pwdump"
#define DEFAULT_NETDB_EXPORT_FILENAME "/var/pwhois/NETDB.pwdump"
#define DEFAULT_ORGDB_EXPORT_FILENAME "/var/pwhois/ORGDB.pwdump"
#define DEFAULT_POCDB_EXPORT_FILENAME "/var/pwhois/POCDB.pwdump"
#define DEFAULT_ROUDB_EXPORT_FILENAME "/var/pwhois/ROUDB.pwdump"

char ACLDB_EXPORT_FILENAME[MAX_PATH];
char ASNDB_EXPORT_FILENAME[MAX_PATH];
char GEODB_EXPORT_FILENAME[MAX_PATH];
char NETDB_EXPORT_FILENAME[MAX_PATH];
char ORGDB_EXPORT_FILENAME[MAX_PATH];
char POCDB_EXPORT_FILENAME[MAX_PATH];
char ROUDB_EXPORT_FILENAME[MAX_PATH];

int FASTLOAD=0;

char reportpath[MAX_PATH];

char VERSION[]="2.2.1.0";
char PROGNAME[]="Prefix WhoIs";
char PROGNAMESHORT[]="pwhoisd";
char COPYRIGHT[]="Copyright (c) 2005-14 VOSTROM Holdings, Inc." ;

/* options descriptor */
static struct option longopts[] =
{
	{"help",		no_argument,		NULL,			'h'},
	{"verbose",		no_argument,		NULL,			'v'},
	{"version",		no_argument,		NULL,			'V'},
	{"logfile",		required_argument,	NULL,			'l'},
	{"configfile",	required_argument,	NULL,			'c'},
	{"daemon",		no_argument,		NULL,			'd'},
	{"pidfile",		required_argument,	NULL,			'0'},
	{"port",		required_argument,	NULL,			'p'},
	{"bind",		required_argument,	NULL,			'b'},
	{"uid",			required_argument,	NULL,			'u'},
	{"gid",			required_argument,	NULL,			'g'},
	{"limit-max-queries",required_argument,NULL,		'm'},
	{"no-load",		no_argument,		NULL,			'1'},
	{"router-id",	required_argument,	NULL,			'r'},
	{"report",		required_argument,	NULL,			'R'},
	{NULL,			0,					NULL,			0}
};

static char PID_FileName[MAX_PATH]=DEFAULT_PIDFILE;
static int LISTEN_QUEUE_LENGTH=5;
static int THREADS_POOL_LENGTH=20;
//static pwhois_thread_cb * threads_pool=0;

void usage()
{
	printf("usage: pwhois [*options*]\n\n"
		   "  -h, --help         display this help and exit\n"
		   "  -v, --verbose      be verbose about what you do (add more -v's to increase verbosity: above v=2 is considered debug)\n"
		   "  -V, --version      output version information and exit\n"
		   "  -l, --logfile f    write misc progress output to logfile instead of stdout\n"
		   "  -c, --configfile f   read startup settings from configuration file: default is %s \n"
		   "  -d, --daemon       start in the background\n"
		   "  --pidfile          use alternative PID file location: default is %s\n"
		   "  -p, --port <n>     port number to listen on: defaults to %d\n"
		   "  --b|bind <ip>      the IP address to bind on: defaults to all interfaces (*)\n"
		   "  -u, --uid          the effective user to run as \n"
		   "  -g, --gid          the effective group to run as \n"
		   "  -R, --report path  write rotating CSV reports of activity into directory"
		   "  --limit-max-queries <n>  The maximum number of queries (per IP/per day) default is %d\n"
		   "  -r, --router-id <id>  the router id to use for this server; useful if there is more that one set of data\n"
		   "     in the database and the server should only serve responses from one set of data.\n"
		   "  --no-load          Do not load data -- for testing purposes\n",
		   DEFAULT_CONFIG, DEFAULT_PIDFILE, DEFAULT_WHOIS_PORT, DEFAULT_MAX_QUERIES);
	
	exit(0);
}

void getVersion()
{
	printf("%s (%s) %s\n\n",PROGNAME,VERSION,COPYRIGHT);
	exit(0);
}

static int all_digits (register char const *const s)
{
	register char const *r;
	
	for (r = s; *r; r++)
		if (!isdigit (*r))
			return 0;
	return 1;
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
	int status,itmp;
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
		exit(0);
	}
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
		
		if(!strcmp(param,"pwhoisd.listenq"))
		{
			itmp=atoi(value);
			if(itmp>=5)
				LISTEN_QUEUE_LENGTH=itmp;
		}
		else if(!strcmp(param,"pwhoisd.threadsq"))
		{
			itmp=atoi(value);
			if(itmp>=2)
				THREADS_POOL_LENGTH=itmp;
		}
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
		else if(!strcmp(param,"fastload"))
		{
			itmp=atoi(value);
			if(itmp)
				FASTLOAD=1;
			else
				FASTLOAD=0;
		}
	}
	fclose(cfgFile);
	regfree(&re);
}

void Daemonize()
{
	FILE *pidFp;
	register int childpid, fd;
	if(getppid()==1)
	{
		for(fd =0;fd<NOFILE; fd++)
		{
			close(fd);
		}
		errno=0;
		chdir("/");
		umask(0);
	}
	/*
	 Ignore the terminal signal for BSD
	 */
#ifdef SIGTTOU
	signal(SIGTTOU,SIG_IGN);
#endif
#ifdef SIGTTIN
	signal(SIGTTIN, SIG_IGN);
#endif
#ifdef SIGTSTP
	signal(SIGTSTP,SIG_IGN);
#endif
	/*
	 fork the process and exit from the parent .Let the daemon start in child
	 */
	if((childpid =fork())>0)
	{ 
		//Parent process
		pidFp= fopen(PID_FileName,	"w+");
		if(pidFp == NULL)
		{
			printf("Could not open file %s", PID_FileName);
		}
		else
		{
			printf("pid= %d \n",childpid);
			fprintf(pidFp,"%d\n",childpid);
			fclose(pidFp);
		}
		exit(0);
	}
	//child process
	if (setsid() < 0)
	{
		printf("Can't change the process group\n");
	}
}

void sigTermination(int stub)
{
	(void)stub;
	log_printf(0, "Terminate pwhoisd\n");
	closeLogger();
	exit(0);
}

int StartServer(uint32_t bindaddr, int port, int uid, int gid)
{
	int listenfd;
	int sockopt;
	struct sockaddr_in serv_addr;
	struct linger fix_ling;

	signal(SIGURG,SIG_IGN);
	signal(SIGPIPE,SIG_IGN);
	//Open TCPIP socket
	if((listenfd=socket(AF_INET,SOCK_STREAM,0))<0)
	{
		log_printf(0, "Server:can't open stream socket: (errno: %d).\n", errno);
		return errno;
	}
	fix_ling.l_onoff=1;
	fix_ling.l_linger=1;
	if(setsockopt(listenfd,SOL_SOCKET,SO_LINGER,&fix_ling,sizeof(fix_ling))<0)
	{
		log_printf(0,"Server can not setsockopt (SO_LINGER): (errno: %d).\n", errno);
		return errno;
	}
	sockopt=1;
	if(setsockopt(listenfd,SOL_SOCKET,SO_REUSEADDR,&sockopt,sizeof(sockopt))<0)
	{
		log_printf(0,"Server can not setsockopt (SO_REUSEADDR): (errno: %d).\n", errno);
		return errno;
	}
#ifdef SO_REUSEPORT
	sockopt=1;
	if(setsockopt(listenfd,SOL_SOCKET,SO_REUSEPORT,&sockopt,sizeof(sockopt))<0)
	{
		log_printf(0,"Server can not setsockopt (SO_REUSEPORT): (errno: %d).\n", errno);
		return errno;
	}
#endif
	/*sockopt=1;
	if(setsockopt(listenfd,SOL_SOCKET,SO_KEEPALIVE,&sockopt,sizeof(sockopt))<0)
	{
		log_printf(0,"Server can not setsockopt (SO_KEEPALIVE): (errno: %d).\n", errno);
		return errno;
	}*/
	bzero((char*)&serv_addr,sizeof(serv_addr));
	serv_addr.sin_family= AF_INET;
	serv_addr.sin_addr.s_addr= bindaddr;
	serv_addr.sin_port= htons(port);
	if(bind(listenfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		log_printf(0,"Server can not bind to the local address: (errno: %d).\n", errno);
		return errno;
	}
	listen(listenfd,LISTEN_QUEUE_LENGTH);
	setuid(uid);
	setgid(gid);
    //save port for getVersion request
    save_listen_port(port);
	initialize_threads(listenfd, sizeof(serv_addr), THREADS_POOL_LENGTH);
    return 0;
}

int main (int argc, char * argv[])
{
	int ch, option_errors=0, portno=DEFAULT_WHOIS_PORT, runasdaemon=0;
	int get_version_request=0;
	int uid=DEFAULT_UID, gid=DEFAULT_GID, no_load=0, filt_by_router=0, router_id=0;
	char logpath[MAX_PATH];
	char cfgpath[MAX_PATH];
	//char pidpath[MAX_PATH];
	struct in_addr bindaddr;

	//Initialize default values
	bindaddr.s_addr=INADDR_ANY;
	reportpath[0]='\0';
	strncpy(cfgpath,DEFAULT_CONFIG,MAX_PATH);
	strncpy(logpath,DEFAULT_LOGFILE,MAX_PATH);
	
    while((ch = getopt_long(argc, argv, "hvVl:R:c:dp:b:u:g:m:r:", longopts, NULL)) != -1)
	{
		switch(ch)
		{
			case 'R':
				strncpy(reportpath,optarg,MAX_PATH);
				break;
			case 'v':
				inc_verbose_level();
				break;
			case 'V':
				//we will execute this request later because we need get all command line arguments
				get_version_request=1;
				break;
			case 'l':
				strncpy(logpath,optarg,MAX_PATH);
				break;
			case 'c':
				strncpy(cfgpath,optarg,MAX_PATH);
				break;
			case 'd':
				runasdaemon=1;
				break;
			case '0':
				strncpy(PID_FileName,optarg,MAX_PATH);
				break;
			case 'p':
				if (strlen (optarg) == 0 || !all_digits (optarg))
				{
					fprintf(stderr, "Invalid argument for -p option: %s\n\n", optarg);
					option_errors++;
					break;
				}
				portno = atoi (optarg);
				if (portno <= 0 || portno >= 65536)
				{
					fprintf(stderr, "Invalid argument for -p option: %s\n\n", optarg);
					option_errors++;
				}
				break;
			case 'b':
				if(!inet_aton(optarg,&bindaddr))
				{
					fprintf(stderr,"Can't parse ip (%s)\n\n",optarg);
					option_errors++;
				}
				break;
			case 'u':
				if (strlen (optarg) == 0 || !all_digits (optarg))
				{
					fprintf(stderr, "Invalid argument for -u option: %s\n\n", optarg);
					option_errors++;
					break;
				}
				uid = atoi (optarg);
				if (uid == 0 || uid >= 65536)
				{
					fprintf(stderr, "Invalid argument for -u option: %s\n\n", optarg);
					option_errors++;
				}
				break;
			case 'g':
				if (strlen (optarg) == 0 || !all_digits (optarg))
				{
					fprintf(stderr, "Invalid argument for -g option: %s\n\n", optarg);
					option_errors++;
					break;
				}
				gid = atoi (optarg);
				if (gid == 0 || gid >= 65536)
				{
					fprintf(stderr, "Invalid argument for -g option: %s\n\n", optarg);
					option_errors++;
				}
				break;
			case 'm':
				if (strlen (optarg) == 0 || !all_digits (optarg))
				{
					fprintf(stderr, "Invalid argument for -m option: %s\n\n", optarg);
					option_errors++;
					break;
				}
                setQueriesLimit(atoi(optarg));
				break;
			case '1':
				no_load=1;
				break;
			case 'r':
				if (strlen (optarg) == 0 || !all_digits (optarg))
				{
					fprintf(stderr, "Invalid argument for -r option: %s\n\n", optarg);
					option_errors++;
					break;
				}
				router_id = atoi (optarg);
				filt_by_router=1;
				break;
			case 'h':
			default:
				usage();
				break;
		}
	}
	if(option_errors)
		usage();
	if(get_version_request)
		getVersion();
	readConfigFile(cfgpath);
	if (!FASTLOAD)
	{
		fprintf(stderr, "Fastload option MUST be set!\n");
		return 1;
	}
	if(runasdaemon)
	{
		//daemonize here, before database loading
		Daemonize();
	}
	if(initLogger(logpath)!=0)
	{
		fprintf(stderr, "Can't open logfile: %s\n\n", logpath);
		exit(0);
	}
	//load ACL
	loadACL_fromFile(ACLDB_EXPORT_FILENAME);
	//Start server here
	if(StartServer(bindaddr.s_addr, portno, uid, gid))
		return 0;
	signal(SIGINT, sigTermination);
	signal(SIGHUP, databaseReload);
	signal(SIGTERM, sigTermination);
	signal(SIGKILL, sigTermination);
	signal(SIGUSR1, ACL_Reload_fromFile);
	signal(SIGUSR2, ACL_Reload_fromFile);
	signal(SIGQUIT,SIG_IGN); // Ignore the SIGQUIT signal
	SetupFilterParameters(filt_by_router, router_id);
	if(no_load)
		EnableEchoServer();
	else
		databaseReload(0);
	//suspend main thread
	while(1)
		pause();
    return 0;
}
