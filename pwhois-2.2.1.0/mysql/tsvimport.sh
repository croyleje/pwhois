#!/bin/bash
for f in *.tsv
do
echo Importing $f
time mysql -u root -e "LOAD DATA LOCAL INFILE '`pwd`/$f' \
INTO TABLE pwhois.${f:0:$((${#f}-4))} FIELDS TERMINATED BY '\t' \
LINES TERMINATED BY '\n'; COMMIT;" pwhois
done
