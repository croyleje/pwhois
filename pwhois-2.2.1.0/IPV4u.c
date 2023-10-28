/*
 *  IPV4.c
 *  
 *	Copyright 2007 VOSTROM Holdings, Inc.  
 *  This file is part of the Distribution.  See the file COPYING for details.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "IPV4u.h"

static unsigned int own_i2a(char* dest, unsigned int x)
{
	register unsigned int tmp=x;
	register unsigned int len=0;
	if(x>=100)
	{
		*dest++=tmp/100+'0';
		tmp=tmp%100;
		++len;
	}
	if(x>=10)
	{
		*dest++=tmp/10+'0';
		tmp=tmp%10;
		++len;
	}
	*dest++=tmp+'0';
	return len+1;
}

static int own_getipsize(unsigned char *ip)
{
	int sz=7; //at least
	int i;
	for(i=0;i<4;i++)
	{
		if(ip[i]>9)
			sz++;
		if(ip[i]>99)
			sz++;
	}
	return sz;
}

char *own_inet_ntoa_r(struct in_addr in,char* buf,int sz)
{
	unsigned int len;
	unsigned char *ip=(unsigned char*)&in;
	if(sz<own_getipsize(ip))
		return NULL;
	len =own_i2a(buf    ,ip[0]); buf[len]='.'; ++len;
	len+=own_i2a(buf+len,ip[1]); buf[len]='.'; ++len;
	len+=own_i2a(buf+len,ip[2]); buf[len]='.'; ++len;
	len+=own_i2a(buf+len,ip[3]); buf[len]=0;
	return buf;
}

void decimal_to_bytes(unsigned long ip, unsigned char * bytes)
{
    unsigned long netip;
    unsigned char * p;
    int i;
    p=(unsigned char *)&netip;
    netip=htonl(ip);
    for(i=0;i<4;i++)
        bytes[i]=p[i];
}

char* ipv4_decimal_to_quaddot(unsigned long network, char* str, int sz)
{
    struct in_addr tmpaddr;
    tmpaddr.s_addr=htonl(network);
	
	if(str == NULL) return str;
	
	/* thread safe versions */
	//addr2ascii(AF_INET, &tmpaddr.s_addr, sizeof(tmpaddr.s_addr), str);
	return own_inet_ntoa_r(tmpaddr, str, sz);
}

int ipv4_quaddot_to_decimal(char * quaddot, unsigned long * result)
{
    struct in_addr tmpaddr;
    if(!inet_aton(quaddot, &tmpaddr) )
    {
        return -1;
    }
    result[0]=ntohl(tmpaddr.s_addr);
    return 0;
}

char *ipv4_dflt_netmask(char * ip)
{
    int a,b,c,d,cidr,r;
    if(strchr(ip,'/')!= NULL) 
        r = sscanf(ip,"%3d.%3d.%3d.%3d/%2d",&a,&b,&c,&d,&cidr);
	else
		r= sscanf(ip,"%3d.%3d.%3d.%3d",&a,&b,&c,&d);
   if(a <= 127)
       return "255.0.0.0";
   if(a <=191)
       return "255.255.0.0";
   return "255.255.255.0";
}

int ipv4_is_valid_quaddot(char * ip)
{
    int a,b,c,d,cidr,length;
    int r = sscanf(ip,"%3d.%3d.%3d.%3d/%2d",&a,&b,&c,&d,&cidr);
    length=strlen(ip);

    if(r<4 || (r==4 && length>16) || length > 19)
        return 0;
    if(a<0 || a>255 || b<0 || b>255 || c<0 || c>255 || d<0 || d>255 || (r>4 && cidr>32))
        return 0;

    return 1;
}

int ipv4_netrange2cidr(unsigned long begip, unsigned long endip)
{
	int r,msk,i,b[4],e[4];
	b[0]=(begip>>24)&0xFF;
	b[1]=(begip>>16)&0xFF;
	b[2]=(begip>>8)&0xFF;
	b[3]=begip&0xFF;
	e[0]=(endip>>24)&0xFF;
	e[1]=(endip>>16)&0xFF;
	e[2]=(endip>>8)&0xFF;
	e[3]=endip&0xFF;

    for(r=0,i=0;i<4;i++)
    {
        if(b[i]==e[i])
            r+=8;
        else
        {
            for(msk=0x0080;msk && (b[i] & msk) == (e[i] & msk);msk>>=1)
                r++;
            break;
        }
    }
	return r;
}

int ipv4_msk2cidr(char * s)
{
	int b[4];
	int r,msk,i;
    if(!ipv4_is_valid_quaddot(s))
        return -1;

    sscanf(s,"%3d.%3d.%3d.%3d",b,b+1,b+2,b+3);
    for(r=0,i=0;i<4;i++)
    {
        if(b[i]==0x00FF)
            r+=8;
        else
        {
            for(msk=0x0080;msk && (b[i] & msk);msk>>=1)
                r++;
            break;
        }
    }

    return r;
}

void ipv4_parse(char * inputIP, char *outputIP, char *outputMsk)
{
    int a,b,c,d,e;
    char * cidr;
    if(!ipv4_is_valid_quaddot(inputIP))
    {
        outputIP[0]=0;
        outputMsk[0]=0;
        return;
    }
    cidr=strchr(inputIP,'/');
    if(cidr)
    {
        sscanf(inputIP,"%3d.%3d.%3d.%3d/%2d",&a,&b,&c,&d,&e);
        cidr[0]=0;
        strcpy(outputIP,inputIP);
        cidr[0]='/';
        cidr++;
        strcpy(outputMsk,cidr);
    }
    else
    {
        strcpy(outputIP,inputIP);
        outputMsk[0]=0;
    }
}

char * ipv4_cidr2msk(int inputCidr, char * maskBuf)
{
    int b[4];
    int i,msk;
    if(inputCidr>32)
        return NULL;
    for(i=0;i<4;i++)
    {
        if(inputCidr>7)
        {
            b[i]=0x00FF;
            inputCidr-=8;
        }
        else
        {
            b[i]=0;
            if(inputCidr)
            {
                for(msk=0x0080;inputCidr;inputCidr--,msk>>=1)
                    b[i]|=msk;
            }
        }
    }
    sprintf(maskBuf,"%d.%d.%d.%d",b[0],b[1],b[2],b[3]);
	return maskBuf;
}

char* ipv4_network(char * ipAddress, int inputCidr, char * network)
{
    char ipMask[50];
    unsigned long addr,mask;
	char str[20];

    if(ipv4_quaddot_to_decimal(ipAddress, &addr)<0)
        return NULL;
    if(!inputCidr)
        inputCidr=ipv4_msk2cidr(ipv4_dflt_netmask(ipAddress));
    ipv4_cidr2msk(inputCidr, ipMask);
    if(ipv4_quaddot_to_decimal(ipMask, &mask)<0)
        return NULL;

    sprintf(network,"%s/%d",ipv4_decimal_to_quaddot(addr&mask, str, 20),inputCidr);
    return network;
}

int ipv4_in_network(char* ipAddress1,int cidr1,char *ipAddress2,int cidr2)
{
    char net1[50],net2[50];
    if(!ipv4_is_valid_quaddot(ipAddress1) || !ipv4_is_valid_quaddot(ipAddress2))
        return 0;
    if( strcmp(ipAddress1,"255.255.255.255")==0 || strcmp(ipAddress1,"0.0.0.0")==0 || 
        strcmp(ipAddress1,"255.255.255.255")==0 || strcmp(ipAddress1,"0.0.0.0")==0)
        return 0;
    if(!cidr1 || cidr1==32)
    {
        if(cidr2>0)
            return 0;
        if(!strcmp(ipAddress1,ipAddress2))
            return 1;
        return 0;
    }
    if(!cidr2 || cidr2==32)
    {
        ipv4_network(ipAddress1, cidr1, net1);
        ipv4_network(ipAddress2, cidr1, net2);
    }
    else
    if(cidr2<cidr1)
    {
        ipv4_network(ipAddress1, cidr2, net1);
        ipv4_network(ipAddress2, cidr2, net2);
    }
    else
    {
        ipv4_network(ipAddress1, cidr1, net1);
        ipv4_network(ipAddress2, cidr1, net2);
    }
    if(!strcmp(net1,net2))
        return 1;
    return 0;
 }
