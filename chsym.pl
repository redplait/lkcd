#!perl -w
# script to check presense of kernel symbols
# 30 nov 2022 (c) redplait
use strict;
use warnings;
use Getopt::Std;

use vars qw/$opt_v/;

sub HELP_MESSAGE()
{
  printf STDERR<<EOF;
Usage: $0 [options] system.map [files]
Options:
 -v - verbose mode
EOF
  exit(8);
}

# two global hashes for symbols - one for uniq and one for duplicated
my %g_syms;
my $g_syms_cnt = 0;
my %g_dup_syms;
my $g_dup_cnt;

# parse Systen.map and fill global hashes
sub parse_map
{
  my $fname = shift;
  my($fh, $str, $name);
  open($fh, '<', $fname) or die("cannot open file $fname, error $!");
  while( $str = <$fh> )
  {
    chomp $str;
    next if ( $str !~ / \S (\S+)$/ );
    $name = $1;
    next if ( exists $g_dup_syms{$name} );
    if ( exists $g_syms{$name} )
    {
      delete $g_syms{$name};
      $g_syms_cnt--;
      $g_dup_syms{$name} = 1;
      $g_dup_cnt++;
      next;
    }
    $g_syms{$name} = 1;
    $g_syms_cnt++;
  }
  close $fh;
}

# check some symbol
sub check_sym
{
  my($fname, $ln, $sym) = @_;
printf("%s line %d: %s\n", $fname, $ln, $sym) if defined($opt_v);
  if ( exists $g_dup_syms{$sym} )
  {
    printf("%s line %d: symbol %s has several occurences\n", $fname, $ln, $sym);
    return;
  }
  return if exists $g_syms{$sym};
  printf("%s line %d: unknown symbol %s\n", $fname, $ln, $sym);
}

sub parse_src
{
  my $fn = shift;
  my($str, $fh, $ln);
  open($fh, '<', $fn) or die("canno open src file $fn, error $!");
  $ln = 0;
  while ( $str = <$fh> )
  {
    chomp $str;
    $ln++;
    next if ( $str =~ /^\s*\/\// ); # skip // comments
    # for lkcd_km.c
    for ( $str =~ /lkcd_lookup_name\s*\(\s*\"(.*)\"/ )
    {
      check_sym($fn, $ln, $1);
      next;
    }
    # for lkmem.cc
    while ( $str =~ /get_addr\(\"([^\"]+)\"/g )
    {
      check_sym($fn, $ln, $1);
    }
  }
  close $fh;
}

# main
my $status = getopts("v");
HELP_MESSAGE() if ( !$status );
HELP_MESSAGE() if ( $#ARGV == -1 );
my $sm = shift @ARGV;
printf("symbols from %s\n", $sm) if defined($opt_v);
parse_map $sm;
if ( $#ARGV == -1 )
{
  printf("%d dup %d\n", $g_syms_cnt, $g_dup_cnt);
} else {
  foreach my $fn ( @ARGV )
  {
    # printf("process %s\n", $fn);
    parse_src($fn);
  }
}