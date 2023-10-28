#!/bin/sh
PREFIX=/usr/local
# check for perl modules

echo " =-=-=-= PWHOIS Server Installer =-=-=-=";
ANSWER=1;
read -p "Are you ready to install pwhoisd, setup the database, etc. onto this system? [Y,n] " ANSWER_IN ;
if [ "$ANSWER_IN" == "" ]; then
	ANSWER=1;
elif [ "$ANSWER_IN" == "Y" ] || [ "$ANSWER_IN" == "y" ]; then
	ANSWER=1;
else
	exit 0;
fi

echo "Installing PERL modules ..."

perl -MCPAN -e "install DBI";
perl -MCPAN -e "install Time::Format";
perl -MCPAN -e "install Log::Dispatch";
perl -MCPAN -e "install Net::DNS";
perl -MCPAN -e "install Net::Telnet";
perl -MCPAN -e "install Net::CIDR";
perl -MCPAN -e "install RPSL::Parser";
perl -MCPAN -e "install DBD::mysql";

# add user accounts
echo "We are now going to create a user/group for the pwhois process to run as"
DEFAULT_USERNAME='pwhois';
read -p  "Username? [$DEFAULT_USERNAME] " USERNAME_IN;
if [ "$USERNAME_IN" == "" ]; then
	USERNAME=$DEFAULT_USERNAME;
else
	USERNAME=$USERNAME_IN;
fi

DEFAULT_UID=512;
read -p "UID? [$DEFAULT_UID] " UID_IN;
if [ "$UID_IN" == "" ]; then
	CUID=$DEFAULT_UID;
else
	CUID=$UID_IN;
fi

DEFAULT_GROUPNAME='pwhois';
read -p "Group name? [$DEFAULT_GROUPNAME] " GROUPNAME_IN;
if [ "$GROUPNAME_IN" == "" ]; then
        GROUPNAME=$DEFAULT_GROUPNAME;
else
	GROUPNAME=$GROUPNAME_IN;
fi

DEFAULT_GID=512;
read -p "GID? [$DEFAULT_GID] " GID_IN;
if [ "$GID_IN" == "" ]; then
        CGID=$DEFAULT_GID;
else
	CGID=$GID_IN;
fi

/usr/sbin/pw groupadd $GROUPNAME -g $CGID
/usr/sbin/pw useradd $USERNAME -u $CUID -g $GROUPNAME \
	-d "/nonexistent" -s "/bin/false" -c "PWhois Server"


# install the files
install -o root -g 0 -m 0754 pwhoisd $PREFIX/sbin/pwhoisd
install -o pwhois -g pwhois -m 0754 pwhois-updatedb $PREFIX/sbin/pwhois-updatedb
install -o root -g 0 -m 0754 pwhois.cron /etc/cron.d/pwhois
touch /var/log/pwhoisd.log
chown $USERNAME:$GROUPNAME /var/log/pwhoisd.log
chmod 0640 /var/log/pwhoisd.log
touch /var/log/pwhois-updatedb.log
chown $USERNAME:$GROUPNAME /var/log/pwhois-updatedb.log
chmod 0640 /var/log/pwhois-updatedb.log
install -d -o $USERNAME -g $GROUPNAME -m 0750 /etc/pwhois
install -o $USERNAME -g $GROUPNAME -m 0640 pwhoisd.conf /etc/pwhois/pwhoisd.conf
mkdir /var/pwhois
chown $USERNAME:$USERNAME /var/pwhois

# create database
ANSWER=0
read -p "Do you want to create the database now? [Y,n] " ANSWER_IN;
if [ "$ANSWER_IN" == "Y" ] || [ "$ANSWER_IN" == "y" ] || [ "$ANSWER_IN" == "YES" ] || [ "$ANSWER_IN" == "Yes" ] || [ "$ANSWER_IN" == "yes" ]; then
	ANSWER=1;
fi

if [ "$ANSWER" -ne 1 ]; then
	echo "You will need to create the database manually.  See the mysql/ directories for more information.";
	exit 0;
fi

read -p "What type of database system are we using? (mysql) [mysql] " DB_TYPE_IN;
if [ "$DB_TYPE_IN" == "" ]; then
	cd postgresql; sh ./initdb.sh;
elif [ "$DB_TYPE_IN" == "mysql" ]; then
	cd mysql; sh ./initdb.sh
else
	echo "Error: invalid database type specified";
	exit 1;
fi

echo "The PWHOIS server is now installed. "
echo "Run '/etc/init.d/pwhoisd start' to start the server for the first time, after running '$PREFIX/sbin/pwhois-updatedb' to populate the database.  "
echo "Depending upon your operating system, you may need to edit or restart the CRON daemon to reread the changes to the configuration.";
echo "Also take a look at /etc/pwhois/pwhoisd.conf as you may need to edit these settings.";
