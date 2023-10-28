-- ALTER TABLE ipcitylatlong ADD CONSTRAINT ipcitylatlong_pk PRIMARY KEY (ipfrom, ipto);
-- CREATE UNIQUE INDEX as_index_a ON asn (id);
-- ALTER TABLE asn ADD CONSTRAINT as_index_a PRIMARY KEY (id);
-- ALTER TABLE asn MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT;
ALTER TABLE asn ADD UNIQUE INDEX as_index_b (asn);
ALTER TABLE asn ADD INDEX as_index_c (org_id);
--
-- ALTER TABLE bgp_routes_history ADD CONSTRAINT bgp_routes_history_id PRIMARY KEY (id);
-- ALTER TABLE bgp_routes_history MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT;
ALTER TABLE bgp_routes_history ADD INDEX bgp_routes_history_index_a (asn);
ALTER TABLE bgp_routes_history ADD INDEX bgp_routes_history_index_b (modifydate);
ALTER TABLE bgp_routes ADD INDEX bgp_routes_index_a (network);
ALTER TABLE bgp_routes ADD INDEX bgp_routes_index_b (asn);
ALTER TABLE bgp_routes ADD INDEX bgp_routes_index_c (modifydate);
ALTER TABLE bgp_routes ADD INDEX bgp_routes_index_d (best_route, status);
-- CREATE UNIQUE INDEX bgp_routes_index_id ON bgp_routes (id);
-- ALTER TABLE bgp_routes ADD CONSTRAINT bgp_routes_index_id PRIMARY KEY (id);
-- ALTER TABLE bgp_routes MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT;
ALTER TABLE ipcitylatlong ADD INDEX ipcitylatlong_index_b (countryshort, countrylong);
ALTER TABLE ipcitylatlong ADD INDEX ipcitylatlong_index_c (ipregion);
ALTER TABLE ipcitylatlong ADD INDEX ipcitylatlong_index_d (ipcity);
ALTER TABLE ipcitylatlong ADD INDEX ipcitylatlong_index_e (iplatitude, iplongitude);
-- CREATE UNIQUE INDEX netblock_index_a ON netblock (id);
-- ALTER TABLE netblock ADD CONSTRAINT netblock_index_a PRIMARY KEY (id);
-- ALTER TABLE netblock MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT;
ALTER TABLE netblock ADD INDEX netblock_index_b (nethandle);
ALTER TABLE netblock ADD INDEX netblock_index_c (network, enetrange);
ALTER TABLE netblock ADD INDEX netblock_index_d (org_id);
ALTER TABLE netblock ADD INDEX netblock_index_e (netname);
ALTER TABLE netblock ADD INDEX KEY netblock_index_a (modifydate);
ALTER TABLE netblock ADD INDEX KEY netblock_index_f (source,status);
-- CREATE UNIQUE INDEX organization_index_a ON organization (id);
-- ALTER TABLE organization ADD CONSTRAINT organization_index_a PRIMARY KEY (id);
-- ALTER TABLE organization MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT;
ALTER TABLE organization ADD INDEX organization_index_b (org_id);
-- Postgres had UNIQUE but MySQL either need to set all org_id to case sensitive or unique
ALTER TABLE organization ADD INDEX organization_index_c (orgname);
ALTER TABLE organization ADD INDEX organization_index_d (adminhandle);
ALTER TABLE organization ADD INDEX organization_index_e (techhandle);
-- CREATE UNIQUE INDEX poc_index_a ON poc (id);
-- ALTER TABLE poc ADD CONSTRAINT poc_index_a PRIMARY KEY (id);
-- ALTER TABLE poc MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT;
ALTER TABLE poc ADD UNIQUE INDEX poc_index_b (pochandle);
ALTER TABLE poc ADD INDEX poc_index_c (lastname, firstname, middlename);
ALTER TABLE poc ADD INDEX poc_index_d (country, state, city);
ALTER TABLE poc ADD INDEX poc_index_e (mailbox);
--
-- ALTER TABLE pwhois_acl ADD CONSTRAINT pwhois_acl_id PRIMARY KEY (id);
-- ALTER TABLE pwhois_acl MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT;
-- ALTER TABLE pwhois_acl ADD UNIQUE INDEX ipcidr (ip, cidr);