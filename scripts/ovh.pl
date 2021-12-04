#!perl -w
# lame try to estimate overhead of ebpf jit
# 4 dec 2021 (c) redplait
use strict;
use warnings;

my($str, $st, $state, $fh);
die("Where is input file?") if ( $#ARGV == -1 );
open($fh, '<', $ARGV[0]) or die("cannot open $ARGV[0], error $!");

$st = 0;
$state = 0;
my $total_len = 0;
my $total_odd = 0;
my $curr_len = 0;
my $odd_len = 0;
# state vars
my $reg;
my $prev_asm = '';

while($str = <$fh>)
{
  chomp $str;
  if ( !$st )
  {
    next if ( $str !~ /^prog_idr at/ );
    $st = 1;
    next;
  }
  # ok, try to parse
  if ( $str !~ /^([0-9a-f]{16}) ([0-9a-f]+)\s+(\w.*)$/i )
  {
     $state = 0;
     $total_len += $curr_len;
     $total_odd += $odd_len;
     $curr_len = $odd_len = 0;
     next;
  }
  my $this_len = length($2);
  $curr_len += $this_len;
  # state 1: mov reg, rbp                 3 byte
  # state 2: add reg, 0xffffffffffffffa0  4 bytes
  my $asm = $3;
# printf("%s state %d\n", $asm, $state);
  if ( $asm =~ /^mov r(\w+), rbp/ )
  {
    $reg = $1;
    $state = 1;
    next;
  }
  if ( ($state == 1) && $asm =~ /^add r(\w+), 0x/ && ($1 eq $reg) )
  {
    # odd len - lea rsi, [rbp-0x18] is 4 bytes
    # so 3 + 4 - 4 = 3
    $odd_len += 3;
    $state = 0;
    next;
  }
  # state 3: mov reg, 0xconst
  # state 4: add reg, 0xconst
  if ( $asm =~ /^mov r(\w+), 0x/ )
  {
    $reg = $1;
    $state = 3;
    next;
  }
  if ( ($state == 3) && $asm =~ /^add r(\w+), 0x/ && ($1 eq $reg) )
  {
    $odd_len += $this_len; # bcs whole second add instr is odd
    $state = 0;
    next;
  }
  # add/sub reg, 0x1 instead of inc/dec
  if ( $asm =~ /^(add|sub) r(\w+), 0x1$/ )
  {
    $odd_len++;
    $state = 0;
    next;
  }
  # mov reg, reg
  if ( $asm =~ /mov r(ax|bx|dx|cx), r(ax|bx|dx|cx)/ )
  {
    # push reg/pop reg - 2 byte
    $odd_len++;
    $state = 0;
    next;    
  }
  if ( $asm eq $prev_asm )
  {
    $odd_len += $this_len; # bcs whole second add instr is odd
  }
  $prev_asm = $asm;
  $state = 0;
}

close $fh;
# dump results
printf("total: %d odd %d\n", $total_len, $total_odd);