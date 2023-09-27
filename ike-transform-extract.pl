#!/usr/bin/perl
# IKE Transforms Extractor
# by Tengku Zahasman

use strict;
use warnings;
use Getopt::Long;
use File::Basename;

my $basename = basename($0);

# usage information 
sub show_help {
	print <<HELP;
****************************************
VPN Transforms Extractor - by TZ

To extract VPN transforms enumeration 
out of test scripts, ie: testingdb1.ts
****************************************

Usage: ./$basename -f <filename>

Example: ./$basename -f testingdb1.ts
	
HELP
	exit 1;
}

# declare variables
my $file = 'testingdb1.ts';
my $help = 0;
my $transform;

my %enc = (
				"1", 'DES',
				"2", 'IDEA',
				"3", 'Blowfish',
				"4", 'RC5',
				"5", '3DES',
				"6", 'CAST',
				"7", 'AES',
				"7,14=128", 'AES(128)',
				"7,14=192", 'AES(192)',
				"7,14=256", 'AES(256)',
				);

my %hash = (
				"1", 'MD5',
				"2", 'SHA1',
				"3", 'Tiger',
				"4", 'SHA2-256',
				"5", 'SHA2-384',
				"6", 'SHA2-512',
				);

my %auth = (
				"1", 'Pre-Shared Key',
				"2", 'DSS Signatures',
				"3", 'RSA signatures',
				"4", 'Encryption with RSA',
				"5", 'Revised encryption with RSA',
				"64221", 'Hybrid Mode',
				"65001", 'XAUTH',
				);
				
my %dh = (
				"1", 'modp768',
				"2", 'modp1024',
				"3", 'ec2n155',
				"4", 'ec2n185',
				"5", 'modp1536',
				"6", 'ec2ngf163Rand',
				"7", 'ec2ngf163Koblitz',
				"8", 'ec2ngf283Rand',
				"9", 'ec2ngf283Koblitz',
				"10", 'ec2ngf409Rand',
				"11", 'ec2ngf409Koblitz',
				"12", 'ec2ngf571Rand',
				"13", 'ec2ngf571Koblitz',
				"14", 'modp2048',
				"15", 'modp3072',
				"16", 'modp4096',
				"17", 'modp6144',
				"18", 'modp8192',
				);

GetOptions(
	"f=s" => \$file,
	'h'	  => \$help,
) or show_help;

$help and show_help;

sub showme {
	open (FILE, $file) or die "Cannot open ".$file.": ".$!;
	
	my @trans;
	my $start = 0;
	
	while(<FILE>) {
	
		if (/Summary of Transforms/) {
			$start = 1;
		}
		
		if (/(.*) Mode Transform\: \[(.+,.+,.+,.+)\] found \((\d+\.\d+\.\d+\.\d+)\)/ && $start == 1) {
		
			$transform = $2;
		
			@trans = split(/\,/,$transform);
			
			# encryption has a weird format because AES have a few different key lengths
			# if enc=7 (which means AES), format will be 7,14=xxx, so this will corrupt the split
			# let's fix this if this is the case
			if ($trans[0] eq "7") {
				$trans[0] = $trans[0].",".$trans[1];
				$trans[1] = $trans[2];
				$trans[2] = $trans[3];
				$trans[3] = $trans[4];
				
				$transform =~s/\,14\=/\//g;
			}
			
			print $1 . "\t" . $3 . "\t" . 
				(!defined($enc{$trans[0]}) ? "undef:".$trans[0]: $enc{$trans[0]}) . "," . 
				(!defined($hash{$trans[1]}) ? "undef:".$trans[1]: $hash{$trans[1]}) . "," . 
				(!defined($auth{$trans[2]}) ? "undef:".$trans[2]: $auth{$trans[2]}) . "," . 
				(!defined($dh{$trans[3]}) ? "undef:".$trans[3] : $trans[3].":".$dh{$trans[3]}) . "\t" . $transform . "\n";
		}
		
		if (/========================================/ && $start == 1) {
			$start = 0;
		}
		
	}
	close (FILE);
}

showme();
