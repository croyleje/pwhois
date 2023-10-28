#!/bin/bash
DBUSER='root';

echo 'Enter the name of the database to create: [pwhois] ';
read DATABASE_IN;
if [ "$DATABASE_IN" == "" ]; then
	DATABASE='pwhois';
else
	DATABASE="$DATABASE_IN";
fi

echo 'Enter the database user to own this database: [pwhois] ';
read USER_IN;
if [ "$USER_IN" == "" ]; then
        USER='pwhois';
else
	USER="$USER_IN";
fi

echo 'Enter the password for this user: [$pwhois$] ';
read PASSWD_IN;
if [ "$PASSWD_IN" == "" ]; then
        PASSWD='$pwhois$';
else
	PASSWD="$PASSWD_IN";
fi

mysql -u root << END
CREATE DATABASE $DATABASE;
CREATE USER '$USER'@'localhost' IDENTIFIED BY '$PASSWD';
GRANT ALL PRIVILEGES ON $DATABASE.* TO '$USER'@'localhost';
END

mysql -u "$USER" -p"$PASSWD" "$DATABASE" < ./createdb.sql

