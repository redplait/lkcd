#!perl -w
# dirty script to count amount of modules sections names
use strict;
use warnings;

my $pfx = '/sys/module';

sub process_mod
{
  my($name, $db) = @_;
  my($d, $str, $fname, $sname);
  $fname = $pfx . '/' . $name . '/sections';
  return 0 if ( !opendir($d, $fname) );
  while( $str = readdir($d) )
  {
    $sname = $fname . '/' . $str;
    next if ( ! -f $sname );
    $db->{$str}++;
  }
  closedir($d);
  return 1;
}

# main
my %db;
my($total, $processed, $d, $str, $fname);
opendir($d, $pfx) or die("cannot opendir $pfx, error $!");
while($str = readdir($d))
{
  $total++;
  $processed += process_mod($str, \%db);
}
closedir($d);
printf("total %d processed %d\n", $total, $processed);
foreach $str ( sort { $db{$a} <=> $db{$b} } keys %db )
{
  printf("%d %s\n", $db{$str}, $str);
}