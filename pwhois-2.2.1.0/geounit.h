/*
 *  geounit.h
 *  pwhoisd
 *	Copyright 2007-13 VOSTROM Holdings, Inc.  
 *  This file is part of the Distribution.  See the file COPYING for details.
 */

#ifndef GEOUNIT_H
#define GEOUNIT_H

struct geo_country_struct;
struct geo_region_struct;
struct geo_location_struct;
struct geo_iprange_struct;

typedef struct geo_country_struct geo_country;
typedef struct geo_region_struct geo_region;
typedef struct geo_location_struct geo_location;
typedef struct geo_iprange_struct geo_iprange;

typedef struct geo_country_struct * p_geo_country;
typedef struct geo_region_struct * p_geo_region;
typedef struct geo_location_struct * p_geo_location;
typedef struct geo_iprange_struct * p_geo_iprange;

struct geo_country_struct
{
	char shortname[3];
	char * longname;
	unsigned long regCount;
	unsigned long firstReg;
};
struct geo_region_struct
{
	geo_country * country;
	char * region;
	unsigned long locCount;
	unsigned long firstLoc;
};
struct geo_location_struct
{
	geo_region * region;
	char * city;
	double latitude;
	double longitude;
	unsigned long rngCount;
	unsigned long firstRng;
};
struct geo_iprange_struct
{
	geo_location * location;
	unsigned long ipfrom;
	unsigned long ipto;
};

p_geo_iprange FindIPRange(unsigned long ip);
void CleanGeoData();
int LoadGeoData_fromFile(char * fname);
void CleanGeoData_fromFile();

#endif
