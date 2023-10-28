ALTER TABLE pwhois_acl ADD COLUMN cidr SMALLINT DEFAULT 32 NOT NULL AFTER ip;
ALTER TABLE pwhois_acl DROP INDEX pwhois_acl_index_a;
ALTER TABLE pwhois_acl ADD UNIQUE INDEX ipcidr (ip, cidr);
