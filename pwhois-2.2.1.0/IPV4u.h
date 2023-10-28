/*
 *  IPV4.h
 *
 *	Copyright 2007 VOSTROM Holdings, Inc.  
 *  This file is part of the Distribution.  See the file COPYING for details.
 */

#include <netinet/in.h>

char *own_inet_ntoa_r(struct in_addr in,char* buf,int sz);
void decimal_to_bytes(unsigned long ip, unsigned char * bytes);
char * ipv4_decimal_to_quaddot(unsigned long network, char* str, int sz);
int ipv4_quaddot_to_decimal(char * quaddot, unsigned long * result);
char *ipv4_dflt_netmask(char * ip);
int ipv4_is_valid_quaddot(char * ip);
int ipv4_msk2cidr(char * s);
void ipv4_parse(char * inputIP,char *outputIP,char *outputMsk );
char * ipv4_cidr2msk(int inputCidr, char * maskBuf);
char* ipv4_network(char * ipAddress, int inputCidr, char * network);
int ipv4_in_network(char* ipAddress1,int cidr1,char *ipAddress2,int cidr2);
int ipv4_netrange2cidr(unsigned long begip, unsigned long endip);
