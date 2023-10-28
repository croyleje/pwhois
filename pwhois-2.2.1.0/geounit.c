/*
 *  geounit.c
 *
 *	Copyright 2007-13 VOSTROM Holdings, Inc.  
 *  This file is part of the Distribution.  See the file COPYING for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "geounit.h"
#include "tst_malloc.h"
#include <string.h>
#include "logger.h"
#include "pwhois_thread.h"

static char * geo_strings=NULL;

static p_geo_iprange allRanges=NULL;
static p_geo_iprange * rangesLocIndex=NULL;
static unsigned long allRngCount=0;

static p_geo_country allCountries=NULL;
static unsigned long allCntCount=0;

static p_geo_region allRegions=NULL;
static unsigned long allRegCount=0;

static p_geo_location allLocations=NULL;
static unsigned long allLocCount=0;

//predeclarations
static unsigned long internalFindIPRange(unsigned long from, unsigned long step, unsigned long ip);

static void loadAllCountries_fromFile(FILE * inpf, uint32_t cnt);
static void loadAllRegions_fromFile(FILE * inpf, uint32_t cnt);
static void loadAllLocations_fromFile(FILE * inpf, uint32_t cnt);
static void loadAllIPRanges_fromFile(FILE * inpf, uint32_t cnt);
static void loadRangesLocIndex_fromFile(FILE * inpf, uint32_t cnt);

static unsigned long internalFindIPRange(unsigned long from, unsigned long step, unsigned long ip)
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

p_geo_iprange FindIPRange(unsigned long ip)
{
    unsigned long resultidx;
    if(!allRngCount)
        return NULL;
    resultidx=internalFindIPRange(0, 1000000, ip);
    resultidx=internalFindIPRange(resultidx, 10000, ip);
    resultidx=internalFindIPRange(resultidx, 100, ip);
    resultidx=internalFindIPRange(resultidx, 1, ip);
    if(allRanges[resultidx].ipfrom > ip)
        return NULL;
    return allRanges+resultidx;
}

void CleanGeoData()
{
	unsigned int i;
	if(allRanges)
	{
		tst_free(allRanges);
	}
	if(allCountries)
	{
		for(i=0;i<allCntCount;i++)
		{
			if(allCountries[i].longname)
				tst_free(allCountries[i].longname);
		}
		tst_free(allCountries);
	}
	if(allRegions)
	{
		for(i=0;i<allRegCount;i++)
		{
			if(allRegions[i].region)
				tst_free(allRegions[i].region);
		}
		tst_free(allRegions);
	}
	if(allLocations)
	{
		for(i=0;i<allLocCount;i++)
		{
			if(allLocations[i].city)
				tst_free(allLocations[i].city);
		}
		tst_free(allLocations);
	}
	if(rangesLocIndex)
	{
		tst_free(rangesLocIndex);
	}

	allRanges=NULL;
	allCountries=NULL;
	allRegions=NULL;
	allLocations=NULL;
	rangesLocIndex=NULL;
}
/*----------------------------------------- Fast load -----------------------------------------*/
static void loadAllCountries_fromFile(FILE * inpf, uint32_t cnt)
{
	unsigned long i;
	uint32_t ruint;
	
	inc_loading_step("GEO (COUNTRIES)",cnt);
	allCountries = tst_malloc( sizeof(geo_country) * cnt );
	if(!allCountries)
	{
		return;
	}
	allCntCount=cnt;
	for(i = 0; i < cnt; i++)
	{
		fread(allCountries[i].shortname, 1, 3, inpf);
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allCountries[i].longname=geo_strings+ruint;
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allCountries[i].regCount=ruint;
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allCountries[i].firstReg=ruint;
		inc_loading_step_counter();
	}
}

static void loadAllRegions_fromFile(FILE * inpf, uint32_t cnt)
{
	unsigned long i;
	uint32_t ruint;
	
	inc_loading_step("GEO (REGIONS)",cnt);
	allRegions = tst_malloc( sizeof(geo_region) * cnt );
	if(!allRegions)
	{
		return;
	}
	allRegCount=cnt;
	for(i=0; i < cnt; i++)
	{
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allRegions[i].country=allCountries+ruint;
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allRegions[i].region=geo_strings+ruint;
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allRegions[i].locCount=ruint;
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allRegions[i].firstLoc=ruint;
		inc_loading_step_counter();
	}
}

#ifdef BIG_ENDIAN
double ntohd(unsigned long long ull)
{
	double ret;
	memcpy((void *)&ret, (void *)&ull, sizeof(unsigned long long));
	return ret;
}
#else
double ntohd(unsigned long long ull)
{
	char b[8];
	register char *p = (char *)(&ull);
	double ret;
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

static void loadAllLocations_fromFile(FILE * inpf, uint32_t cnt)
{
	unsigned long i;
	uint32_t ruint;
	unsigned long long rull;
	
	inc_loading_step("GEO (LOCATIONS)",cnt);
	allLocations = tst_malloc( sizeof(geo_location) * cnt );
	if(!allLocations)
	{
		return;
	}
	allLocCount=cnt;
	for(i=0; i < cnt; i++)
	{
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allLocations[i].region=allRegions+ruint;
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allLocations[i].city=geo_strings+ruint;
		fread(&rull, sizeof(unsigned long long), 1, inpf);
		allLocations[i].latitude=ntohd(rull);
		fread(&rull, sizeof(unsigned long long), 1, inpf);
		allLocations[i].longitude=ntohd(rull);
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allLocations[i].rngCount=ruint;
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allLocations[i].firstRng=ruint;
		inc_loading_step_counter();
	}
}

static void loadAllIPRanges_fromFile(FILE * inpf, uint32_t cnt)
{
	unsigned long i;
	uint32_t ruint;
	
	inc_loading_step("GEO (IP RANGES)",cnt);
	allRanges=tst_malloc(sizeof(geo_iprange)*cnt);
	if(!allRanges)
	{
		return;
	}
	allRngCount=cnt;
	for (i = 0; i < cnt; i++)
	{
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allRanges[i].location=allLocations+ruint;
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allRanges[i].ipfrom=ruint;
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		allRanges[i].ipto=ruint;
		inc_loading_step_counter();
	}
}

static void loadRangesLocIndex_fromFile(FILE * inpf, uint32_t cnt)
{
	unsigned long i;
	uint32_t ruint;
	
	inc_loading_step("GEO (BINDING)",cnt);
	rangesLocIndex = tst_malloc( sizeof(p_geo_iprange) * cnt );
	if(!rangesLocIndex)
	{
		return;
	}
	//we don't need change it because we did it in LoadAllIPRanges
	//allRngCount=cnt;
	for (i = 0; i < cnt; i++)
	{
		fread(&ruint, sizeof(uint32_t), 1, inpf);
		ruint=ntohl(ruint);
		rangesLocIndex[i]=allRanges+ruint;
		inc_loading_step_counter();
	}
}

int LoadGeoData_fromFile(char * fname)
{
	FILE * inpf;
	uint32_t ulCntCount,ulRegCount,ulLocCount,ulRngCount;
	size_t stringArraySize;
	struct stat fileinfo;
	
	inpf=fopen(fname, "rb");
	if(!inpf)
	{
		log_printf(0, "Can't open import file %s\n", fname);
		return 0;
	}
	fstat(fileno(inpf), &fileinfo);
	stringArraySize=fileinfo.st_size;
	fread(&ulCntCount, sizeof(uint32_t), 1, inpf);
	ulCntCount=ntohl(ulCntCount);
	fread(&ulRegCount, sizeof(uint32_t), 1, inpf);
	ulRegCount=ntohl(ulRegCount);
	fread(&ulLocCount, sizeof(uint32_t), 1, inpf);
	ulLocCount=ntohl(ulLocCount);
	fread(&ulRngCount, sizeof(uint32_t), 1, inpf);
	ulRngCount=ntohl(ulRngCount);
	stringArraySize-=(sizeof(uint32_t)*4);
	stringArraySize-=(3+sizeof(uint32_t)*3)*ulCntCount;
	stringArraySize-=(sizeof(uint32_t)*4)*ulRegCount;
	stringArraySize-=(sizeof(uint32_t)*4+sizeof(unsigned long long)*2)*ulLocCount;
	stringArraySize-=(sizeof(uint32_t)*4)*ulRngCount;
	
	geo_strings=tst_malloc(stringArraySize);
	if(!geo_strings)
	{
		fclose(inpf);
		return 0;
	}
	
	loadAllCountries_fromFile(inpf, ulCntCount);
	if(!allCountries)
	{
		tst_free(geo_strings);
		geo_strings=NULL;
		fclose(inpf);
		return 0;
	}
	
	loadAllRegions_fromFile(inpf, ulRegCount);
	if(!allRegions)
	{
		tst_free(geo_strings);
		geo_strings=NULL;
		tst_free(allCountries);
		allCountries=NULL;
		fclose(inpf);
		return 0;
	}
	
	loadAllLocations_fromFile(inpf, ulLocCount);
	if(!allLocations)
	{
		tst_free(geo_strings);
		geo_strings=NULL;
		tst_free(allCountries);
		allCountries=NULL;
		tst_free(allRegions);
		allRegions=NULL;
		fclose(inpf);
		return 0;
	}
	
	loadAllIPRanges_fromFile(inpf, ulRngCount);
	if(!allRanges)
	{
		tst_free(geo_strings);
		geo_strings=NULL;
		tst_free(allCountries);
		allCountries=NULL;
		tst_free(allRegions);
		allRegions=NULL;
		tst_free(allLocations);
		allLocations=NULL;
		fclose(inpf);
		return 0;
	}
	
	loadRangesLocIndex_fromFile(inpf, ulRngCount);
	if(!rangesLocIndex)
	{
		tst_free(geo_strings);
		geo_strings=NULL;
		tst_free(allCountries);
		allCountries=NULL;
		tst_free(allRegions);
		allRegions=NULL;
		tst_free(allLocations);
		allLocations=NULL;
		tst_free(allRanges);
		allRanges=NULL;
		fclose(inpf);
		return 0;
	}
	inc_loading_step("GEO (STRINGS)",1);
	fread(geo_strings, 1, stringArraySize, inpf);
	fclose(inpf);
	return 1;
}

void CleanGeoData_fromFile()
{
	if(geo_strings)
		tst_free(geo_strings);
	geo_strings=NULL;
	if(allCountries)
		tst_free(allCountries);
	allCountries=NULL;
	allCntCount=0;
	if(allRegions)
		tst_free(allRegions);
	allRegions=NULL;
	allRegCount=0;
	if(allLocations)
		tst_free(allLocations);
	allLocations=NULL;
	allLocCount=0;
	if(allRanges)
		tst_free(allRanges);
	allRanges=NULL;
	if(rangesLocIndex)
		tst_free(rangesLocIndex);
	rangesLocIndex=NULL;
	allRngCount=0;
}
