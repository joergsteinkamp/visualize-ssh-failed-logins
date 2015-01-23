#!/usr/bin/perl

use strict;
use IO::Uncompress::Gunzip  qw(gunzip);
use DBI;

# Which year is the first entry from (oldest auth.log.*.gz file)
my $start_year = 2014;

# lines with relevant sshd authentication info
my @flogin;

# open the compressed file, oldest first
for (my $i=99; $i>1; $i--) {
  my $authfile = sprintf("/var/log/auth.log.%i.gz",$i);
  if (-f $authfile) {
    my $z = new IO::Uncompress::Gunzip($authfile);
    while (<$z>) {
      # ignore everything else than sshd
      next if ! /sshd/;
      # ignore local network
      next if /127\.0\.0\.1/;
      next if /192\.168/;
      # ignore socket connections
      next if /Read from socket failed/;
      # ignore shutdown/restart meassages
      next if /Received signal 15; terminating/;
      next if /Server listening on 0.0.0.0 port 22/;
      chomp;
      push(@flogin, $_);
    } 
  }
}

# open the uncompressed files
foreach ("auth.log.1", "auth.log") {
  open(FHD, "/var/log/$_");
  my @lines = <FHD>;

  foreach (@lines) {
    # ignore everything else than sshd
    next if ! /sshd/;
    # ignore local network
    next if /127\.0\.0\.1/;
    next if /192\.168/;
    # ignore socket connections
    next if /Read from socket failed/;
    # ignore shutdown/restart meassages
    next if /Received signal 15; terminating/;
    next if /Server listening on 0.0.0.0 port 22/;
    chomp;
    push(@flogin, $_);
  }
}

# open a sqlite file
my $dbh = DBI->connect(          
    "dbi:SQLite:dbname=failed_ssh_logins.db", 
    "",
    "",
    { RaiseError => 1, AutoCommit => 1}
) or die $DBI::errstr;

# prepare the database
$dbh->do("DROP TABLE IF EXISTS event");
$dbh->do("DROP TABLE IF EXISTS ip");
$dbh->do("DROP TABLE IF EXISTS user");
$dbh->do("CREATE TABLE event(id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT, ipid INTEGER, userid INTEGER)");
$dbh->do("CREATE TABLE ip(id INTEGER PRIMARY KEY AUTOINCREMENT, v4 TEXT, subnetid INTEGER)");
$dbh->do("CREATE TABLE user(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)");  
$dbh->do("INSERT INTO user(name) VALUES(\"\")");

# extract the date string from the log file
# This may be different for other Linux distributions
# and need to be adopted.
my $prev_month = "Dec";
my $year       = $start_year;
foreach (@flogin) {
  my $ip    = "";
  my $user  = "";
  my $month = substr($_, 0 , 3);
  my $date  = substr($_, 0 , 15);

  # new year
  $year++ if ($prev_month eq "Dec" && $month eq "Jan");
  $prev_month = $month;

  # extract the IPv4 address
  if (/Connection closed by .* \[preauth\]/) {
    s/.*Connection closed by //;
    s/ \[preauth\]$//;
    $ip = $_;
  } elsif (/Did not receive identification string from .*/) {
    s/.*Did not receive identification string from //;
    $ip = $_
  } elsif (/Received disconnect from .* \[preauth\]/) {
    s/.*Received disconnect from //;
    s/:.*\[preauth\]$//;
    $ip = $_;

  # extract the username
  } elsif (/Invalid user .* from .*/) {
    $user = $_; 
    $user =~ s/.*Invalid user //;
    $user =~ s/ from.*//;
    s/.*Invalid user .* from //;
    $ip = $_;
  } elsif (/Failed password for root from /) {
    s/.*Failed password for root from //;
    s/ port.*//;
    $ip=$_;
    $user="root";
  } else {
    # print "$_";
    next;
  }

  # check if the username already exists in the db
  my $rows;
  my $sqluserid = 1;
  if ($user ne "") {
    my $sth = $dbh->prepare("SELECT id FROM user WHERE name=\"$user\"");
    $sth->execute();

    my @arr = $sth->fetchrow_array();
    $sth->finish();

    # if not put it in
    if ($arr[0] eq "") {
      $dbh->do("INSERT INTO user(name) VALUES(\"$user\")");
    }

    # save the userid for later
    $sth = $dbh->prepare("SELECT id FROM user WHERE name=\"$user\"");
    $sth->execute();
    $sqluserid = ($sth->fetchrow_array())[0];
    $sth->finish();
  }

  # do the same for the IPv4 address
  my $sqlipid = -1;
  if ($ip ne "") {
    my $sth = $dbh->prepare( "SELECT id FROM ip WHERE v4=\"$ip\"" );
    $sth->execute();

    my @arr = $sth->fetchrow_array();
    $sth->finish();

    if ($arr[0] eq "") {
      $dbh->do("INSERT INTO ip(v4) VALUES(\"$ip\")");
    }
    $sth = $dbh->prepare("SELECT id FROM ip WHERE v4=\"$ip\"");
    $sth->execute();
    $sqlipid = ($sth->fetchrow_array())[0];
    $sth->finish();
  }
  # and save the failed login event
  $dbh->do("INSERT INTO event(date, userid, ipid) VALUES(\"$date $year\", $sqluserid, $sqlipid)");
}

$dbh->disconnect();
