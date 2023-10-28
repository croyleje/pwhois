


CREATE TABLE asn (
  id int(11) NOT NULL AUTO_INCREMENT,
  ashandle varchar(30) NOT NULL,
  org_id varchar(30) NOT NULL,
  asn bigint(20) NOT NULL,
  asname varchar(64) NOT NULL,
  registerdate date DEFAULT NULL,
  comment varchar(2000) DEFAULT NULL,
  updatedate date NOT NULL,
  adminhandle varchar(30) DEFAULT NULL,
  techhandle varchar(30) DEFAULT NULL,
  source smallint(6) NOT NULL DEFAULT 1,
  createdate int(11) NOT NULL,
  modifydate int(11) NOT NULL,
  as_orgname varchar(128) DEFAULT NULL,
  mailbox varchar(64) DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY as_index_b (asn),
  KEY as_index_c (org_id)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE bgp_routes (
  id int(11) NOT NULL AUTO_INCREMENT,
  router_id bigint(20) NOT NULL,
  network bigint(20) NOT NULL,
  cidr smallint(6) DEFAULT NULL,
  next_hop bigint(20) NOT NULL,
  asn int(11) NOT NULL,
  asn_paths varchar(255) NOT NULL,
  createdate int(11) NOT NULL,
  modifydate int(11) NOT NULL,
  status int(11) NOT NULL DEFAULT 1,
  best_route smallint(6) NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  KEY bgp_routes_index_a (network),
  KEY bgp_routes_index_b (asn),
  KEY bgp_routes_index_c (modifydate),
  KEY bgp_routes_index_d (best_route,status)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE bgp_routes_history (
  id int(11) NOT NULL AUTO_INCREMENT,
  route_id bigint(20) NOT NULL,
  asn int(11) NOT NULL,
  asn_paths varchar(255) NOT NULL,
  createdate int(11) NOT NULL,
  modifydate int(11) NOT NULL,
  status int(11) NOT NULL DEFAULT 1,
  best_route smallint(6) NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  KEY bgp_routes_history_index_a (asn),
  KEY bgp_routes_history_index_b (modifydate)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE ipcitylatlong (
  ipfrom bigint(20) NOT NULL DEFAULT 0,
  ipto bigint(20) NOT NULL DEFAULT 0,
  countryshort char(2) NOT NULL,
  countrylong varchar(64) NOT NULL,
  ipregion varchar(128) NOT NULL,
  ipcity varchar(128) NOT NULL,
  iplatitude double DEFAULT NULL,
  iplongitude double DEFAULT NULL,
  PRIMARY KEY (ipfrom,ipto),
  KEY ipcitylatlong_index_b (countryshort,countrylong),
  KEY ipcitylatlong_index_c (ipregion),
  KEY ipcitylatlong_index_d (ipcity),
  KEY ipcitylatlong_index_e (iplatitude,iplongitude)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE netblock (
  id int(11) NOT NULL AUTO_INCREMENT,
  nethandle varchar(30) NOT NULL,
  org_id varchar(30) NOT NULL,
  parent varchar(40) DEFAULT NULL,
  netname varchar(64) NOT NULL,
  netrange varchar(64) DEFAULT NULL,
  network bigint(20) NOT NULL,
  nettype smallint(6) NOT NULL DEFAULT 1,
  registerdate date NOT NULL,
  comment varchar(2000) DEFAULT NULL,
  updatedate date NOT NULL,
  nameserver1 varchar(255) DEFAULT NULL,
  nameserver2 varchar(255) DEFAULT NULL,
  nameserver3 varchar(255) DEFAULT NULL,
  nameserver4 varchar(255) DEFAULT NULL,
  nochandle varchar(30) DEFAULT NULL,
  abusehandle varchar(30) DEFAULT NULL,
  techhandle varchar(30) DEFAULT NULL,
  source smallint(6) NOT NULL DEFAULT 1,
  createdate int(11) NOT NULL,
  modifydate int(11) NOT NULL,
  enetrange bigint(20) DEFAULT NULL,
  orgname varchar(128) DEFAULT NULL,
  mailbox varchar(64) DEFAULT NULL,
  status tinyint(4) NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  KEY netblock_index_b (nethandle),
  KEY netblock_index_c (network,enetrange),
  KEY netblock_index_d (org_id),
  KEY netblock_index_e (netname),
  KEY netblock_index_a (modifydate),
  KEY netblock_index_f (source,status)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE organization (
  id int(11) NOT NULL AUTO_INCREMENT,
  org_id varchar(30) NOT NULL,
  orgname varchar(128) NOT NULL,
  canallocate smallint(6) NOT NULL,
  street1 varchar(255) DEFAULT NULL,
  street2 varchar(128) DEFAULT NULL,
  street3 varchar(128) DEFAULT NULL,
  street4 varchar(128) DEFAULT NULL,
  street5 varchar(128) DEFAULT NULL,
  street6 varchar(128) DEFAULT NULL,
  city varchar(64) DEFAULT NULL,
  state varchar(64) DEFAULT NULL,
  country varchar(2) DEFAULT NULL,
  postalcode varchar(15) DEFAULT NULL,
  registerdate date DEFAULT NULL,
  comment varchar(2000) DEFAULT NULL,
  updatedate date NOT NULL,
  referralserver varchar(255) DEFAULT NULL,
  adminhandle varchar(30) DEFAULT NULL,
  nochandle varchar(30) DEFAULT NULL,
  abusehandle varchar(30) DEFAULT NULL,
  techhandle varchar(30) DEFAULT NULL,
  source smallint(6) NOT NULL DEFAULT 1,
  createdate int(11) NOT NULL,
  modifydate int(11) NOT NULL,
  PRIMARY KEY (id),
  KEY organization_index_c (orgname),
  KEY organization_index_d (adminhandle),
  KEY organization_index_e (techhandle),
  KEY organization_index_b (org_id)
-- Postgres had UNIQUE but for MySQL need either to set all org_id to case sensitive or unique
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE poc (
  id int(11) NOT NULL AUTO_INCREMENT,
  pochandle varchar(64) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL,
  isrole smallint(6) NOT NULL,
  firstname varchar(64) DEFAULT NULL,
  lastname varchar(64) DEFAULT NULL,
  middlename varchar(64) DEFAULT NULL,
  rolename varchar(64) DEFAULT NULL,
  street1 varchar(128) DEFAULT NULL,
  street2 varchar(128) DEFAULT NULL,
  street3 varchar(128) DEFAULT NULL,
  street4 varchar(128) DEFAULT NULL,
  street5 varchar(128) DEFAULT NULL,
  street6 varchar(128) DEFAULT NULL,
  city varchar(64) DEFAULT NULL,
  state varchar(64) DEFAULT NULL,
  country varchar(2) DEFAULT NULL,
  postalcode varchar(15) DEFAULT NULL,
  registerdate date NOT NULL,
  comment varchar(2000) DEFAULT NULL,
  updatedate date NOT NULL,
  officephone varchar(128) DEFAULT NULL,
  mailbox varchar(64) DEFAULT NULL,
  source smallint(6) NOT NULL DEFAULT 1,
  createdate int(11) NOT NULL,
  modifydate int(11) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY poc_index_b (pochandle),
  KEY poc_index_c (lastname,firstname,middlename),
  KEY poc_index_d (country,state,city),
  KEY poc_index_e (mailbox)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE pwhois_acl (
  id int(11) NOT NULL AUTO_INCREMENT,
  ip bigint(20) NOT NULL,
  cidr smallint(6) NOT NULL DEFAULT 32,
  createdate int(11) NOT NULL,
  modifydate int(11) NOT NULL,
  status int(11) NOT NULL DEFAULT 1,
  max_count int(11) NOT NULL DEFAULT 1000,
  comment varchar(128) DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY ipcidr (ip, cidr)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE version (
  name varchar(30) NOT NULL,
  version int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;




