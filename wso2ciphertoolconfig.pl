#!/usr/bin/perl -w
#############################################################################
# Program   wso2ciphertool.pl                                               #
#                                                                           #
# Author    Axel Zuber                                                      #
# Created   11.09.2016                                                      #
#                                                                           #
# Description   scan the wso2 config files for password tags.               #
#               collect the                                                 #
#                 - file name                                               #
#                 - the password location                                   #
#                 - the password text                                       #
#               in the secure vault configuration files                     #
#                 cipher-tools.properties                                   #
#                 cipher-text.properties                                    #
#               for use with the ciphertool.sh utility.                     #
#                                                                           #
# ------------------------------------------------------------------------- #
#                                                                           #
# Input     <carbon_home>/repository/conf                                   #
#                                                                           #
# ------------------------------------------------------------------------- #
#                                                                           #
# Output    <carbon_home>/repository/conf/security/cipher-tool.properties   #
#           <carbon_home>/repository/conf/security/cipher-text.properties   #
#                                                                           #
# ------------------------------------------------------------------------- #
#                                                                           #
# Exit code                                                                 #
#        0 : Successful                                                     #
#        4 : Warnings                                                       #
#        8 : Errors                                                         #
#                                                                           #
# ------------------------------------------------------------------------- #
#                                                                           #
# History                                                                   #
# Ver   Date        Name        Description                                 #
# 1.0   11.09.2016  A. Zuber    Initial version                             #
#                                                                           #
#############################################################################

# ------------------------------------------------------------------------- #
# SAX callback functions                                                    #
# ------------------------------------------------------------------------- #

package ConfigScanner;

use base qw(XML::SAX::Base);

my $verbose      = 0;
my $debug        = 0;
my $headerdone   = 0;

my $elementPath  = [];
my $inPassword   = 0;
my $inName       = 0;
my $currfile;
my $resultset;
my $numPasswords;

# scope $adminpassword explicitly so that it can be assigned in MAIN
our $adminpassword;

sub new()
{
	my $invocant  = shift;
	my $class     = ref($invocant) || $invocant;   # Object or class name
	my $self      = {};                            # initiate our handy hashref
	bless( $self, $class );                        # make it usable

	$currfile     = shift;
	$resultset    = shift;
	$elementPath  = [];
	$headerdone   = 0;
    $numPasswords = 0;

	return $self;
}

# testForPassword : return true if element/attribute name 
#                   match one of the password patterns.
#                   return false for non-matches or for 
#                   matches with a reject-pattern.
sub testForPassword
{
	my ( $string ) = @_;

	return ( (     $string =~ /.*password$/i
				|| $string =~ /.*KeyPassword$/i
                || $string =~ /.*keystorePass$/i
                || $string =~ /ConnectionPassword/
			 )
	      && (     $string !~ /StoreSaltedPassword/
	            && $string !~ /mail\.smtp\.password/
	         )
	);
}

sub attribList2String
{
    my ( $attriblist ) = @_;

    my $s = "";
    map { $s = "$s $_->{attrname}=$_->{attrval}"; } @$attriblist;

    $s =~ s/^\ //;

    return $s;
}

sub getResultSet()      {	return $resultset;      }
sub getPasswordsFound() {   return $numPasswords;   }

##
#   deep copy of element path
##
sub cloneXPath
{
	my @clone = ();
	map { push @clone, $_ } @$elementPath;
	return \@clone;
}

sub addPasswordReference
{
	my ( $pwdText ) = @_;

	# replace reference to password ${admin.password} password text from user-mgt.xml
	# 
	if ($pwdText =~ /^\$\{.+\}$/) 
	{
		SWITCH: {
			($pwdText =~ /admin.password/) && do {
                $pwdText = $adminpassword;
                last SWITCH;
			};
			do {
                die "password reference $pwdText can't be resolved";
			}
		}
	}

    printf "\nFILE : %s\n", $currfile if $verbose && !$debug && !$headerdone;
    $headerdone = 1;

	printf "====>: %s=[%s]%s\n", MAIN::generateXPath($elementPath), $pwdText, $skipPwd?" skipped: yes":"" if $verbose || $debug;

    if (!$skipPwd)
    {
        $numPasswords += 1;

	    push @$resultset,
	      {
	        'file'    => $currfile,
	        'pwdpath' => cloneXPath($elementPath),
	        'pwdtext' => $pwdText
	      }
    }
}

##
#   method names as specified by SAX
##
sub start_element
{
	my ( $self, $data ) = @_;

	my $newElement = $data->{Name};

	my $attributes = $data->{Attributes};
	my $attriblist = ();
	if ( keys %$attributes )
	{
		# 1. scan for identifying attributes
        map {
            my $attrib      = $attributes->{$_};
            my $attribname  = $attrib->{LocalName};
            my $attribvalue = $attrib->{Value};

            push @$attriblist,
              { 'attrname' => $attribname, 'attrval' => $attribvalue };

            # add 'name', 'username' and 'type' attribute values to current element
            $newElement .= "[\@$attribname=\'$attribvalue\']"
              if exists { "name" => 1, "username" => 1, "type" => 1 }->{$attribname};
        } keys %$attributes;

        # 2. scan for passwords 
        map {
            my $attrib      = $attributes->{$_};
            my $attribname  = $attrib->{LocalName};
            my $attribvalue = $attrib->{Value};

            # process passwords configured as element attributes
            if ( testForPassword($attribname) )
            {
                push @$elementPath, $newElement . "[\@$attribname]";
                addPasswordReference($attribvalue);
                pop @$elementPath;
            }

            if ( testForPassword($attribvalue) )
            {
                $inPassword = 1;
            }
        } keys %$attributes;
	}

	push @$elementPath, $newElement;

	if ($debug)
	{
		printf "BEG  : %s\n", $data->{Name};
		printf "ATTR : %s\n", MAIN::attribList2String($attriblist) if scalar $attriblist;
		printf "PATH : %s\n", MAIN::generateXPath($elementPath);
	}

	# pattern-driven state transition

	$inPassword	= 1 if testForPassword( $data->{Name} );
	$inName		= 1	if $data->{Name} =~ /^name$/;
}

sub characters
{
	# method names are specified by SAX
	my ( $self, $data ) = @_;

	my $char = $data->{Data};
	$char =~ tr/\x{d}\x{a}//d;
	$char =~ s/^\s+|\s+$//g;

	if ($debug)
	{
		printf "CHAR : %s\n", $char if $char ne "";
	}

	if ($inName)
	{
		# a 'name' element is converted into an attribute
		# and added to the topmost element on the stack.

		pop @$elementPath;
		my $tos = pop @$elementPath;
		$tos .= "[name=\'$char\']";
		push @$elementPath, $tos;
	}

	addPasswordReference( $data->{Data} ) if $inPassword;
}

sub end_element
{
	# method names are specified by SAX
	my ( $self, $data ) = @_;

	# discard elements without a name

	pop @$elementPath if !$inName;

	# reset state at the end of an element

	$inPassword = 0;
	$inName     = 0;

	if ($debug)
	{
		printf "END  : %s\n", $data->{Name};
		printf "PATH : %s\n", MAIN::generateXPath($elementPath);
	}
}

# ------------------------------------------------------------------------- #
# MAIN program                                                              #
# ------------------------------------------------------------------------- #

package MAIN;

require 5.008;
use strict 'vars';
use warnings;
use utf8;

use Carp qw(carp cluck croak confess);
use File::Basename;
use File::Find;
use File::Spec;
use Getopt::Long;
use Getopt::Std;
use IO::File;
use Time::HiRes qw(clock);
use XML::Parser;
use XML::SAX::ParserFactory;
use XML::Simple;

use POSIX qw(strftime);

# ------------------------------------------------------------------------- #
# global variables                                                          #
# ------------------------------------------------------------------------- #

my @todolist;
my $totalFiles;
my $impactedFiles;
my $totalPasswords;

# ------------------------------------------------------------------------- #
# process the files from the configuration directory                        #
# ------------------------------------------------------------------------- #

# retrieve the the password to replace  
# ${admin.password} references by.
#
sub retrieveAdminPassword
{
    my ( $configpath ) = @_;
    
    my $usermgtxml = "$configpath/user-mgt.xml";

    die "user-mgt.xml not found in $configpath" if ! -f $usermgtxml;

    my $admpwd;

    my $filehandle = IO::File->new("< $usermgtxml") or die "Could not open $usermgtxml";

    # create object
    my $xmlin = new XML::Simple(
        forcearray => 1,
        keeproot   => 1
    );

    # read XML file into an XML hash
    my $xmldata = $xmlin->XMLin($filehandle);
    $filehandle->close();

    $admpwd = $xmldata->{UserManager}[0]->{Realm}[0]->{Configuration}[0]->{AdminUser}[0]->{Password}[0];
    
    if ( ref $admpwd eq "HASH")
    {
    	die "admin password already encrypted in user-mgt.xml";
    }

#   printf "retrieved admin.password $admpwd from $usermgtxml";
    die "admin password not found in user-mgt.xml" if !defined $admpwd;

    return $admpwd;
}


# wanted :  - collect all .xml file names
#             from the /repository/conf tree.
#           - reject out-of-scope files.
sub wanted
{
    my $currfile  = $File::Find::name; # pick the absolute filename

	my $notwanted = 1 if 
	     $currfile eq "." 
	  || $currfile eq ".."
	  || $currfile !~ /.*\.xml$/
      || $currfile =~ qw[/repository/conf/multitenancy/stratos.xml]  # no internet connection to stratos
      || $currfile =~ qw[/repository/conf/tomcat/tomcat-users.xml]   # tomcat not exposed to user
	  ;
	push @todolist, $currfile if !$notwanted;

	return;
}

##
#   parse the input file
##
sub processSingleFile
{
	my ( $infile, $resulthashtable ) = @_;

	printf "\nFILE : %s\n", $infile if $debug;
    $totalFiles += 1;

	my $handler = ConfigScanner->new( $infile, $resulthashtable );
	my $parser  = XML::SAX::ParserFactory->parser( Handler => $handler );

	$parser->parse_uri($infile);

	my $np = $handler->getPasswordsFound();
	if ( $np > 0 )
	{
		$impactedFiles  += 1;
        $totalPasswords += $np;
	}

    return $handler->getResultSet();
}

##
#   parse all files from the todo list
##
sub scanInputFiles
{
	my ( $configpath ) = @_;

	find( \&wanted, $configpath );

	my $result      = [];
    $totalFiles     = 0;
    $impactedFiles  = 0;
    $totalPasswords = 0;

	map { processSingleFile( $_, $result ); } sort @todolist;

	return $result;
}

# ------------------------------------------------------------------------- #
# generate the output files                                                 #
# ------------------------------------------------------------------------- #

# generatePasswordAlias:    convert the element path into a password alias.
#                           skip the first element, since it only brackets
#                           the file contents.

sub generatePasswordAlias
{
	my ( $scannedXPath, $scannedFile ) = @_;

	my $alias    = "";
	my $delim    = "";
	my $state    = 0;
	my $allxmluc = 1;

	map {
		my $newElement = $_;

		if ($state)
		{
			my $pathelem;
			my $pathattr;
			my $isCompound = 0;

			# translate path elements with attributes into
			# the attribute value (required for datasources)
			$allxmluc = 0 if $newElement =~ /^[a-z]/;

			if ( $newElement =~ /(.+)\[[^=]+=\'([^']+)'\]/ )
			{
				$pathelem   = $1;
				$pathattr   = $2;
				$isCompound = 1;
			}
			elsif ( $newElement =~ /(.+)\[\@([^\]]+)\]/ )
			{
				$pathelem   = $1;
				$pathattr   = $2;
				$isCompound = 1;
			}

			if ($isCompound)
			{
			  SWITCH:
				{
                    ( $alias =~ /Server.Service/ && $pathelem =~ /Connector/ ) && do
                    {
                        $newElement = "$pathelem.$pathattr";
                        last SWITCH;
                    };
                    ( $alias =~ /Tomcat/ && $pathelem =~ /user/ ) && do
                    {
                        $newElement = "$pathelem.$pathattr";
                        last SWITCH;
                    };
					( $pathelem =~ /axisconfig/ ) && do
					{
						$newElement = "Axis2";
						last SWITCH;
					};
					( $pathelem =~ /transport(Receiver|Sender)/ ) && do
					{
						$newElement = "$pathelem.$pathattr";
						last SWITCH;
					};
					( $pathelem =~ /Service/ && $pathattr =~ /Catalina/ ) && do
					{
						$newElement = "Server.Service";
						last SWITCH;
					};
					( $pathelem =~ /Environment/ && $pathattr =~ /hybrid/ ) && do
					{
						$alias      = "APIGateway";
						$newElement = "";
						$delim      = "";
						last SWITCH;
					};
					do
					{
						$newElement = $pathattr;
						last SWITCH;
					};
				}
			}

		  SWITCH:
			{
				( $alias =~ /^Axis2.transportSender/ && $pathelem =~ /parameter/ ) && do
				{
					$alias      = "Axis2.Https.Listener";
					$newElement = "";
					$delim      = "";
					last SWITCH;
				};
                ( $alias =~ /^Axis2.transportReceiver/ && $pathelem =~ /parameter/ ) && do
                {
                    $alias      = "Axis2.Https.Sender";
                    $newElement = "";
                    $delim      = "";
                    last SWITCH;
                };
                ( $alias =~ /^Axis2/ && $scannedFile =~ /.*axis2_(.+)\.xml$/ ) && $pathelem =~ /parameter/ && do
                {
                    my $axis2Qualifier = $1 if $scannedFile =~ /.*axis2_(.+)\.xml$/;
                    $axis2Qualifier =~ s/_//g;
                    $alias      = "Axis2.$axis2Qualifier";
                    $newElement = "";
                    $delim      = "";
                    last SWITCH;
                };
                ( $alias =~ /^Security/ && $newElement =~ /(KeyStore)|(TrustStore)/ ) && do
                {
                    $alias      = "Carbon.Security";
                    last SWITCH;
                };
                ( $alias =~ /^Realm.Configuration/ && $newElement =~ /AdminUser/ ) && do
                {
                    $alias      = "UserManager";
                    last SWITCH;
                };
			}

			$alias .= "$delim$newElement";
			$delim = ".";
		}
		else
		{
		  SWITCH:
			{
                ( $newElement =~ /axisconfig/ ) && do
                {
                    $alias = "Axis2";
                    $delim = ".";
                    last SWITCH;
                };
                ( $newElement =~ /tomcat-users/ ) && do
                {
                    $alias = "Tomcat";
                    $delim = ".";
                    last SWITCH;
                };
			}
			$state = 1;
		}
	} @$scannedXPath;

	return { 'ALIAS' => $alias, 'ALLXMLELEMENTSUPPERCASE' => $allxmluc };
}

##
# generateXPath:     create an XPath expression from the element path.
##
sub generateXPath
{
	my ( $elementPath ) = @_;

	my $path = "";

	map {
		my $newElement = $_;

		my $pathelem;
		my $pathattr;
		my $isCompound = 0;

		if ( $newElement =~ /(.+)\[[^=]+=\'([^']+)'\]/ )
		{
			$pathelem   = $1;
			$pathattr   = $2;
			$isCompound = 1;
		}
		elsif ( $newElement =~ /(.+)\[\@([^\]]+)\]/ )
		{
			$pathelem   = $1;
			$pathattr   = $2;
			$isCompound = 1;
		}

		if ($isCompound)
		{
		  SWITCH:
			{
				( $pathelem =~ /axisconfig/ ) && do
				{
					$newElement = "$pathelem";
					last SWITCH;
				};
				( $pathelem =~ /Service/ && $pathattr =~ /Catalina/ ) && do
				{
					$newElement = "Service";
					last SWITCH;
				};
				( $pathelem =~ /Environment/ && $pathattr =~ /hybrid/ ) && do
				{
					$newElement = "Environment";
					last SWITCH;
				};
				do
				{
					last SWITCH;
				};
			}
		}

		$path = "$path/$newElement";

	} @$elementPath;

	return $path;
}

sub getLoggingTime
{
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime(time);

	my $nice_timestamp = sprintf( "%04d.%02d.%02d %02d:%02d:%02d",
								  $year + 1900,
								  $mon + 1, $mday, $hour, $min, $sec );
	return $nice_timestamp;
}

##
#   generateOutputFiles :   create cipher-text.properties and cipher-tool.properties
##
sub generateOutputFiles
{
	my ( $result, $carbonhome, $cipherpath ) = @_;

	my $date = getLoggingTime();

	my $toolname = "cipher-tool.properties";
	my $textname = "cipher-text.properties";

	my $toolhandle;
	my $texthandle;

	if ( $debug )
	{
        $toolname= "-";
        $textname= "-";
	}
	else
	{
        $toolname= "$cipherpath/$toolname";
        $textname= "$cipherpath/$textname";
	}

    $toolhandle = new IO::File(">$toolname");
    $texthandle = new IO::File(">$textname");

	print $toolhandle <<"FOO_BAR";
# cipher-tool.properties. Generated on $date.
# This properties file contains all the aliases to be used in carbon components. 
# If any property need to be secured, you need to add alias name and the value. 
# This value is described as follows.
# The value goes as, the file name//xpath to the property value to be secured,
# true if xml elements start with capital letter. 
# Please check existing property values below.

FOO_BAR

	my $checkDuplicateAlias = {};

	map {
		my $relativeConfigPath = File::Spec->abs2rel( $_->{file}, $carbonhome );
        my $alias = generatePasswordAlias( $_->{pwdpath}, $_->{file} );
        my $aliastext = $alias->{ALIAS};

		if ( exists $checkDuplicateAlias->{$aliastext} )
		{
			my $prevFile = $checkDuplicateAlias->{$aliastext};
			die "alias $aliastext for file $relativeConfigPath already defined for file $prevFile";
		}
		else
		{
			$checkDuplicateAlias->{$aliastext} = $relativeConfigPath;
		}

		printf $toolhandle "%s=%s/%s,%s\n",
		  $aliastext,
		  $relativeConfigPath,
		  generateXPath( $_->{pwdpath} ),
##
#           the true/false label of an XPath expression
#           triggers special processing of named elements.
#           the DOM parser regularly aborts, so set it 
#           always false and verify if this works out. 
##		  
          "false";
#          $alias->{ALLXMLELEMENTSUPPERCASE} ? "true" : "false";

	} @$result;

	printf "\n\n";

	print $texthandle <<"FOO_BAR";
# cipher-text.properties. Generated on $date.
# This is the file based secret repository, used by Secret Manager of synapse secure vault
# By default, This file contains the secret alias names Vs the plain text passwords enclosed with '[]' brackets
# In Production environments, It is recommend to replace those plain text password by the encrypted values. 
# CipherTool can be used for it.

FOO_BAR

	map {
		my $alias = generatePasswordAlias( $_->{pwdpath}, $_->{file} );
		printf $texthandle "%s=[%s]\n", $alias->{ALIAS}, $_->{pwdtext};
	} @$result;


    printf "Found %d passwords in %d out of %d files.\n",
		    $totalPasswords,
		    $impactedFiles,
		    $totalFiles;

    if ( !$debug )
    {
	    printf "Created output files :\n%s\n%s\n",
	            $toolname,
                $textname;
    }
}

########################################################################
##
##      Help screen
##
########################################################################

sub printHelpScreen
{
	my ( $usage ) = @_;
	my @helptext = (
		   '',
		   "wso2ciphertool.pl - create ciphertool properties files from wso2 configuration",
		   '',
		   "$usage",
		   '',
		   "create cipher-text.properties and cipher-tool.properties files",
		   "by scanning wso2 configuration files for plaintext passwords.",
		   '',
		   "Parameters:",
		   '',
		   "location of carbon home directory",
		   '',
		   "Options:",
		   '',
		   "-d  Debug",
		   "-h  print help screen",
           "-v  increase verbosity",
           "-x  print list of xml parsers"
	);

	map { print $_ . "\n"; } @helptext;
}

sub listXMLParsers
{
	my @parsers = @{ XML::SAX->parsers() };

	map
	{
		my $p = $_;
		print "\n", $p->{Name}, "\n";

		map
		{
			my $f = $_;
			print "$f => ", $p->{Features}->{$f}, "\n";

		} sort keys %{ $p->{Features} };

	} @parsers;
}

##
#-----------------------------------------------------------------------
# main
#-----------------------------------------------------------------------
#
{
	my $scriptName = basename($0);
	my $usage      = "Usage: $scriptName [-dhvx] <carbonhome>";

	# Check Options
	my $optStr  = 'dDhHvVxX';
	my %options = ();

	die 'Invalid option(s) given' if ( !getopts( "$optStr", \%options ) );

	$verbose = 1 if exists $options{v};
	$debug = 1 if exists $options{d} || exists $options{D};

	# print help screen
	if ( (!@ARGV || exists $options{h}) && !exists $options{x} )
	{
		printHelpScreen($usage);
		exit 0;
	}

	# print list of xml parsers available for perl
	if ( exists $options{x} )
	{
		listXMLParsers();
		exit 0;
	}

    my $carbonhome = $ARGV[0];
	my $configpath = File::Spec->canonpath("$carbonhome/repository/conf");
	my $cipherpath = File::Spec->canonpath("$carbonhome/repository/conf/security");

	die "CARBON_HOME path $carbonhome does not exist"             if !-d "$carbonhome";
	die "directory $configpath does not exist. check CARBON_HOME" if !-d "$configpath";
    die "directory $cipherpath does not exist. check CARBON_HOME" if !-d "$cipherpath";

    $adminpassword = retrieveAdminPassword( $configpath );

	my $result = scanInputFiles( $configpath );

	generateOutputFiles( $result, $carbonhome, $cipherpath );
}
