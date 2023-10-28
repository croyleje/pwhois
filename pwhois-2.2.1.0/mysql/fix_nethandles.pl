#!/usr/bin/perl

use strict;
use DBI;
use Getopt::Long;

package PWHOIS::App;

my $VERSION = '0.1';
my $DEFAULT_DSN='dbi:mysql:dbname=pwhois';
my $DEFAULT_DB_USERNAME='pwhois';
my $DEFAULT_DB_PASSWORD='';
my $PROGNAME='Fix NetHandle Records';
my $COPYRIGHT="Copyright (c) 2009 VOSTROM Holdings, Inc.\n";

my $dsn = $DEFAULT_DSN;
my $user = $DEFAULT_DB_USERNAME;
my $password = $DEFAULT_DB_PASSWORD;

# database tuning variables for controling how many entries are inserted/updated before a commit occurs
#my $VERY_SMALL_COMMIT_SIZE = 10;
my $SMALL_COMMIT_SIZE = 100;
#my $MEDIUM_COMMIT_SIZE = 1000;
#my $LARGE_COMMIT_SIZE = 10000;
my $DEFAULT_MAX_RECORDS = 1000000;			 # maximum number of records to process before exiting


my $update_sth;
my $select_sth;

my $dbh;
my $logfile;
my $pidfile;
my $log;										# log handle

my $DEBUG = 'false';
my %opt = ();

# use GMT
$ENV{'TZ'} = 'GMT';

sub new {
   my $self = {};
   my $class = shift;
   return bless _init($self), $class
}

sub _init {
   my $self = shift;
   
   return $self
}

sub usage
{
	print STDOUT "usage: $0 -u [*options*]\n\n",
		  "  -?, --help                    display this help and exit\n",
		  "  -V, --version         output version information and exit\n",
		  "  --display-only		   Used for testing/debugging to see what would happen\n",
		  "  [--commit-size <size> ]       Number of records to insert/update before performing a database commit\n",
		  "  [--max-records <size> ]       Maximum number of records to update (Default: $DEFAULT_MAX_RECORDS\n",
		  "  [-v, --verbose ]              Be verbose about what you do\n",

		  "\n\nThis program will update all the records in the netblocks table that \n",
	" were imported or marked as source other than ARIN (1), and fix the nethandle\n",
	" which has no meaning in the context of RPSL, but is used as a network identifer\n",
	" for the update process.  pwhois-updatedb uses this keep track of unique networks\n",
	" for the purposes of associating this with RIR data to prefix data\n",
	"\n",
	"WARNING:  PLEASE BACK-UP YOUR DATABASE.  IF YOU HAVEN'T YET, STOP THIS JOB RIGHT NOW\n",
	" AND DO THAT FIRST!!!.\n",
	"\n",
	"This process may take many hours to run depending on the size of your database\n",
	" and how many netblock records you have.  You can execute this in batches if you want\n",
	" by using the --commit-size and --max-records=X options to process data in smaller chunks\n",
	" Don't run an RPSL import though again unless you fix all the data first -- otherwise you'll\n",
	" end up with duplicate data in the database\n",	 
	"\n\n";

	exit;
}

sub processArgs
{

        Getopt::Long::Configure('no_ignore_case');

        Getopt::Long::GetOptions(\%opt, 'help|h|?', 'version|V', 'display-only',
                   		 'verbose|v+', 
                   		 'update|u',
						 'commit-size:i',
						 'max-records:i',
						  ) or die "Unable to process command-line arguments ... internal error.\n";
        
		usage() if $opt{help};

        # set version output to 0
        if(!defined($opt{verbose})) {
                $opt{verbose} = 0;

                if($opt{verbose} >= 2) {
                        $DEBUG = 'true';
                }
        }

        if($opt{version}) {
                print_version();
                exit(0);
        }
		
		
		 if($opt{version}) {
                print "$0 $VERSION\n";
                print "$COPYRIGHT\n";
                exit;
                }

		if(!defined($opt{'commit-size'})) {
			$opt{'commit-size'} = $SMALL_COMMIT_SIZE;
		}
		
		if(!defined($opt{'max-records'})) {
			$opt{'max-records'} = $DEFAULT_MAX_RECORDS;
		}
		
}


sub handleArgs
{
	my $return = 1;
	
	if($opt{'update'}) {
			update();
		}
	
	$return;
	
	
}

# open the database and create prepared statements
sub openDatabase()
{	
	$dbh = DBI->connect($dsn, $user, $password,
                  { RaiseError => 1, AutoCommit => 0 }) 
		#or $log->log(level=>'error', message=>"Can't open database: $DBI::errstr");
		or die "Can't open database: $DBI::errstr";

	# fix non ARIN data (RPSL parse issue)
	$select_sth = $dbh->prepare(qq(
		SELECT id,nethandle,network,enetrange,netrange FROM netblock
		WHERE source > 1 AND nethandle not like '%-S%'
		ORDER BY id ASC LIMIT ?
	)) or $log->log(level=>'error', message=>"Can't prepare statement: $DBI::errstr");


	$update_sth = $dbh->prepare(qq(
		UPDATE netblock 
		SET nethandle=? WHERE id=?
	)) or $log->log(level=>'error', message=>"Can't prepare statement: $DBI::errstr");			   


	1;
}


# close down the database connection
sub closeDatabase()
{
#	print STDOUT "Database closed dsn=$dsn\n";
	undef $update_sth;
	undef $select_sth;
		
	$dbh->disconnect;
}


sub DESTROY {
   my $self = shift;
   closeDatabase();
   $self->SUPER::DESTROY
}

sub print_version() {
	print STDOUT "$PROGNAME ($VERSION)\n", 
	             "$COPYRIGHT\n\n";

}

# convert decimal integer to quaddot
sub ipv4_decimal_to_quaddot($) {
	my $decimal = shift;
	warn "invalid decimal value provided" if !defined($decimal);
	return "" if !defined($decimal);

	warn "invalid decimal value provided: $decimal" if($decimal < 0 or $decimal > 4294967295);
	return "" if($decimal < 0 or $decimal > 4294967295);
        return join ".", unpack "CCCC", pack "N", $decimal;
}

my $ip_rgx = "\\d+\\.\\d+\\.\\d+\\.\\d+";

# Given an IPv4 address in host, ip/netmask or cidr format
# returns a ip / cidr pair.
sub ipv4_parse($;$) {
  my ($ip,$msk);
  # Called with 2 args, assume first is IP address
  if ( defined $_[1] ) {
    $ip = $_[0];
    $msk= $_[1];
  } else {
    ($ip)  = $_[0] =~ /($ip_rgx)/o;
    ($msk) = $_[0] =~ m!/(.+)!o;
  }

  # Remove white spaces
  $msk =~ s/\s//g if defined $msk;

  # Check Netmask to see if it is a CIDR or Network
  if (defined $msk ) {
    if ($msk =~ /^\d{1,2}$/) {
      # Check cidr
      warn ": invalid cidr: ". $msk ."\n"
        if $msk < 0 or $msk > 32;
    } elsif ($msk =~ /^$ip_rgx$/o ) {
      $msk = ipv4_msk2cidr($msk);
    } else {
      warn ": invalid netmask specification: ". $msk ."\n";
    }
  } else {
    # Host
    return $ip;
  }
  wantarray ? ($ip,$msk) : "$ip/$msk";
}

# Transform a netmask in a CIDR mask length
sub ipv4_msk2cidr($) {
  my $msk = $_[0];
  my @bytes = split /\./, $msk;
  my $cidr = 0;
  for (@bytes) {
    my $bits = unpack( "B*", pack( "C", $_ ) );
    $cidr +=  $bits =~ tr /1/1/;
  }
  return $cidr;
}

# take and IPv4 range and transform to cidr
sub ipv4_netrange2cidr($;$)
{
	my ($begip, $endip) = @_;
	my $msk;
	my $i;
	my $r;

	my @b = (0, 0, 0, 0);
	my @e = (0, 0, 0, 0);
	my $bn = unpack "N", pack "CCCC", split /\./, $begip;
	my $en = unpack "N", pack "CCCC", split /\./, $endip;
	
	$b[0] = ($bn >> 24) & 0xFF;
	$b[1] = ($bn >> 16) & 0xFF;
	$b[2] = ($bn >> 8) & 0xFF;
	$b[3] = $bn & 0xFF;
	$e[0] = ($en >> 24) & 0xFF;
	$e[1] = ($en >> 16) & 0xFF;
	$e[2] = ($en >> 8) & 0xFF;
	$e[3] = $en & 0xFF;

    for($r=0, $i=0 ;$i < 4; $i++)
    {
        if($b[$i]==$e[$i]) {
            $r += 8;
		}
        else
        {
            for($msk=0x0080; $msk && ($b[$i] & $msk) == ($e[$i] & $msk); $msk >>= 1) {
                $r++;
			}
            last;
        }
    }
	return $r;
}



# the new netname format for RPSL data
sub makeNetHandle
{
    my $str = $_[0];
    my ($ip1, $ip2) = $str =~ m/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+-\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/;
    my $nethandle;
	
	# have to use the whole string because they don't have a user-defined nethandle.
	
	my ($net, $cidr);
		
	if(defined($ip1) and defined($ip2)) {
		($net,$cidr) = ipv4_parse($ip1, ipv4_netrange2cidr($ip1, $ip2));
	}
	
    if(defined($ip1)){
        $ip1 =~ s/\./-/g;
        $nethandle = "NET-" . $ip1 . '-S' . $cidr;
    }
    return $nethandle;
}


# the new netname format for RPSL data
# use the ips (quaddot) directly
sub makeNetHandle2
{
    my ($ip1, $ip2) = @_;
    my $nethandle;
	
	# have to use the whole string because they don't have a user-defined nethandle.
	
	my ($net, $cidr);
		
	if(defined($ip1) and defined($ip2)) {
		($net,$cidr) = ipv4_parse($ip1, ipv4_netrange2cidr($ip1, $ip2));
	}
	
    if(defined($ip1)){
        $ip1 =~ s/\./-/g;
        $nethandle = "NET-" . $ip1 . '-S' . $cidr;
    }
    return $nethandle;
}



sub update()
{	
	my $result = $select_sth->execute($opt{'max-records'}) or die "Can't prepare statement: $DBI::errstr";
	my $count = 0;
	while(my ($id,$nethandle,$network,$enetrange,$netrange) = $select_sth->fetchrow_array())
	{
		# skip if we already fixed
		next if $nethandle =~ /^NET.*-S\d{1,2}$/;
	
		my $begip = ipv4_decimal_to_quaddot($network);
		my $endip;
		my $new_nethandle = '';
		
		$endip = ipv4_decimal_to_quaddot($enetrange) if $enetrange ne '' and $enetrange ne '0';
		if($endip eq '') { # parse again (version 3)
			$new_nethandle = makeNetHandle($netrange);
		}
		else {	# use ips directly (version 4)
			$new_nethandle = makeNetHandle2($begip, $endip);
		}
		
		print STDOUT "$id: Update nethandle $nethandle => $new_nethandle\n" if $opt{verbose} >= 1; 
		
		if(!$opt{'display-only'}) {
			my $results = $update_sth->execute($new_nethandle, $id);
			$dbh->commit() if $count % $opt{'commit-size'} == 0;
			print STDOUT "Commit record $count id=$id\n" if $count % $opt{'commit-size'} == 0;
		}
		
		$count++;
	}
	
	$dbh->commit() if !$opt{'display-only'};
	$update_sth->finish();
	$select_sth->finish();

	print STDOUT "Commited a total of $count records\n" if !$opt{'display-only'};
	
}

my $obj = new PWHOIS::App(); 
$obj->processArgs();
$obj->print_version() if $opt{verbose} > 0 and !$opt{logfile};
$obj->openDatabase();
$obj->handleArgs();
$obj->closeDatabase();

1;




