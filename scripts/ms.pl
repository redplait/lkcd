#!perl -w
# dirty script to count amount of modules sections names
use strict;
use warnings;
use File::Find;
use Carp;
use POSIX qw(uname);

my %g_kos;
my $pfx = '/sys/module';
my $g_total = 0;

sub do_readelf
{
  my($name, $s, $db) = @_;
  my($f, $str, $sec);
  if ( !open($f, "readelf -SW \"" . $name . "\"|") )
  {
    carp("cannot run readelf for $name");
    return;
  }
  while( $str = <$f> )
  {
    chomp $str;
    if ( $str =~ /^  \[\s*\d+\]\s+(\S+)\s+/ )
    {
      $sec = $1;
      next if ( !exists $s->{$sec} );
      my $patch = $db->{$sec};
      my @rest = split(" ", $');
# {
# printf("%s sec %s %s\n", $name, $sec, $');
# foreach my $r ( @rest )
# {
#  printf("%s\n", $r);
# } }
      my $size = hex($rest[3]);
      $patch->[1] += $size;
      $g_total += $size;
    }
  }
  close $f;
}

# db is ref to hash where key is section name and value is array
# index 0 - count
# index 1 - total size of all those sections
# index 2 - where is first encountered
sub process_mod
{
  my($name, $db) = @_;
  my($d, $str, $fname, $sname, %sects);
  $fname = $pfx . '/' . $name . '/sections';
  return 0 if ( !opendir($d, $fname) );
  while( $str = readdir($d) )
  {
    next if ( $str eq '.' or $str eq '..' );
    $sname = $fname . '/' . $str;
#    next if ( ! -f $sname );
    $sects{$str} = 1;
    if ( exists $db->{$str} )
    {
      my $r = $db->{$str};
      $r->[0]++;
    } else {
      $db->{$str} = [ 1, 0, $name ];
    }
  }
  closedir($d);
  if ( exists $g_kos{$name} )
  {
    do_readelf($g_kos{$name}, \%sects, $db);
  } else {
    carp("cannot find fullpath for $name");
  }
  return 1;
}

# main
my %db;
my @uname = uname();
my $mod_dir = '/usr/lib/modules/' . $uname[2] . '/';
# check if we have arg - consider it at root dir for modules
$mod_dir = $ARGV[0] if ( -1 != $#ARGV );
# print $mod_dir;
# scan modules for their full paths
my(@dirs, $d, $str);
opendir($d, $mod_dir) or die("cannot opendir $mod_dir, error $!");
while( $str = readdir($d) )
{
  next if ( $str eq '.' or $str eq '..' );
  my $fname = $mod_dir . $str;
  next if ( ! -d $fname || -l $fname );
  push @dirs, $fname;
}
closedir($d);
sub wanted
{
  if ( -f $File::Find::name && $_ =~ /\.ko$/ ) {
    $_ =~ s/\.ko$//;
    $_ =~ s/-/_/g; # replace all - to underscore
    $g_kos{$_} = $File::Find::name;
  }
}
find( \&wanted, @dirs);

my($total, $processed, $fname);
opendir($d, $pfx) or die("cannot opendir $pfx, error $!");
while($str = readdir($d))
{
  next if ( $str eq '.' or $str eq '..' );
  $total++;
  $processed += process_mod($str, \%db);
}
closedir($d);
printf("total %d processed %d\n", $total, $processed);
foreach $str ( sort { $db{$a}->[0] <=> $db{$b}->[0] } keys %db )
{
  printf("%d %d %f %s (%s)\n", $db{$str}->[0], $db{$str}->[1],
   100.0 * ( $db{$str}->[1] / $g_total), $str, $db{$str}->[2]);
}