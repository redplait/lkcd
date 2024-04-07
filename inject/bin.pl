#!perl
use strict;
use warnings;

die("where is arg?") if ( -1 == $#ARGV );
die("no such file") if ! -e $ARGV[0];
my $size = -s $ARGV[0];
my($fh, $b, $idx);
open($fh, '<', $ARGV[0]);
binmode $fh;
for ( $idx = 0; $idx < $size; $idx++ )
{
  sysread($fh, $b, 1);
  $b = unpack('C', $b);
  printf("0x%2.2X,", $b);
  printf("\n") if ( $idx > 10 && 0 == ($idx + 1) % 16 );
}
close $fh;