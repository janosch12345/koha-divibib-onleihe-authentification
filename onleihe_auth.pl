#!/usr/bin/perl


use strict;
use warnings;

use CGI;
use XML::Simple;
use C4::Members;
#use Config;
use Koha::AuthUtils qw(hash_password);
use Digest::MD5 qw(md5_base64);
use C4::Output;
use C4::Context;

my $query = new CGI;

#todays date - f.e. for expired patrons
use DateTime;
my $today = DateTime->today->date;


#Tests


#user credentials
my $userid = $query->param('sno');
my $password = $query->param('pwd');

#empty credentials
if ($userid eq "" or $password eq ""){
	my $ds = {
		status => [-1],
		fsk => [0],
		library => ['<![CDATA[libraryname]]>']
	};
	my $xml;
	$xml = XMLout($ds,XMLDecl => '<?xml version="1.0" encoding="UTF-8"?>',RootName => "response");

	output_with_http_headers $query, undef, $xml, 'xml';
	exit;
}

#checkin login
my ($status,$age) = getUser($userid,$password);

my $fsk = getFSK($age);

#Output
my $ds = {
	status => [$status],
	fsk => [$fsk],
	library => ['<![CDATA[libraryname]]>']
};
my $xml;
$xml = XMLout($ds,XMLDecl => '<?xml version="1.0" encoding="UTF-8"?>',RootName => "response");

output_with_http_headers $query, undef, $xml, 'xml';

### Helpers ###

sub getFSK{
	my $age = $_[0];
	if ($age < 0){$age = 0;}
	my @fsks = (18,16,12,6,0);
	my $i = 0;
	while ($age < $fsks[$i]){
		$i++;
	}
	return $fsks[$i];
}

sub age {
	my $bdaydate = $_[0];
	my ($birth_year, $birth_month, $birth_day)=split(/-/,$bdaydate);
    my ($day, $month, $year) = (localtime)[3..5];
    $year += 1900;
	$month+= 1;
    my $age = $year - $birth_year;
    $age-- unless sprintf("%01d%02d", $month, $day) <= sprintf("%01d%02d", $birth_month, $birth_day);
	return $age;
}

sub getUser {
	my ( $userid,$password ) = @_;
	my $bornum;

	#from Auth.pm
	my $dbh = C4::Context->dbh;
	my $sth =
      	$dbh->prepare(
		"select password,cardnumber,borrowernumber,userid,firstname,surname,branchcode,flags from borrowers where userid=?"
      	);
	$sth->execute($userid);
	if ( $sth->rows ) {
        	my ( $stored_hash, $cardnumber, $borrowernumber, $userid, $firstname, $surname, $branchcode, $flags ) = $sth->fetchrow;

        	if ( checkpw_hash($password, $stored_hash) ) {
			#valid usercredentials
			#my ( $borr ) = C4::Members::GetMemberDetails( $borrowernumber );
			#my ( $borr ) = GetMember( borrowernumber => $borrowernumber );
			my $borr = Koha::Patrons->find( $borrowernumber )->unblessed;
			
			#gesperrter user - debarred
			return("1","0") if defined ($borr->{'debarred'});#gesperrt status = 1
			#nutzerausweis abgelaufen - expired
			if ($borr->{'dateexpiry'} lt $today) { return("-3","0") } #card expired
			#valid user
			return("3",age $borr->{'dateofbirth'});
        	} else {
			#wrong credentials
			return("-2",'0');
		}
	} else {
		$sth = $dbh->prepare(
		  "select password,cardnumber,borrowernumber,userid, firstname,surname,branchcode,flags from borrowers where cardnumber=?"
		  );
		$sth->execute($userid);
		if ( $sth->rows ) {
			my ( $stored_hash, $cardnumber, $borrowernumber, $userid, $firstname,
					$surname, $branchcode, $flags )
				  = $sth->fetchrow;

			if ( checkpw_hash($password, $stored_hash) ) {
					#valid usercredentials
				#my ( $borr ) = C4::Members::GetMemberDetails( $borrowernumber );
				#my ( $borr ) = GetMember( borrowernumber => $borrowernumber );
				my $borr = Koha::Patrons->find( $borrowernumber )->unblessed;
				
				#gesperrter user - debarred
				return("1","0") if defined ($borr->{'debarred'});#gesperrt status = 1
				#nutzerausweis abgelaufen - expired
				if ($borr->{'dateexpiry'} lt $today) { return("-3","0") } #card expired
				#valid user
				return("3",age $borr->{'dateofbirth'});
		    
			} else {
				return ("-2","0");
			}
		} else {#no such user
			return ("-1","0");
		}
	}
	
}

#from Auth.pm
sub checkpw_hash {
    my ( $password, $stored_hash ) = @_;

    return if $stored_hash eq '!';

    # check what encryption algorithm was implemented: Bcrypt - if the hash starts with '$2' it is Bcrypt else md5
    my $hash;
    if ( substr($stored_hash,0,2) eq '$2') {
        $hash = hash_password($password, $stored_hash);
    } else {
        $hash = md5_base64($password);
    }
    return $hash eq $stored_hash;
}

