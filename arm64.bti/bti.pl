#!perl -w
use strict;
use warnings;

my($fp, $str, $addr, $t, $name, %db);
open($fp, '<', $ARGV[0]) or die("cannot open $ARGV[0], error $!\n");
while( $str = <$fp> )
{
  chomp $str;
  next if ( $str !~ /^ffff80*(\S+) T (.*)$/ );
  my $addr = hex($1) - 0x8000000;
  $db{$addr} = $2;
}
close($fp);

# read from no.bti
open($fp, '<', 'no.bti') or die("cannot open no.bti, error $!\n");
while( $str = <$fp>)
{
  chomp $str;
  $addr = hex($str);
  next if ( !exists $db{$addr} );
  printf("%x %s\n", $addr, $db{$addr});
}