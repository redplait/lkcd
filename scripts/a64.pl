#!perl -w
# stupid and terrible implementation of simple and dumb idea - we could optimize asm output for aarch64 placing
# constant literals behind functions reffered to it
# However there are several problems:
#  [!] literal can be shared between several functions, in such case we must leave it in string pool inside .rodata section
#   and yep, we can only find out about it after processing of whole .s file
#  [!] adr opcode has only 12 bit: https://developer.arm.com/documentation/ddi0602/2024-03/Base-Instructions/ADR--Form-PC-relative-address-
#   even worse - it is signed value so range of accessibility is 2 ** 11 / 4 = 2048 bytes / 512 instructions
#  [!] even that's not all - totally unclear how to prioritize which string we should place in .text. For example if we
#   selected first and happened that it's loo long then all remained cannot be added. I choosed to sort all string candidates
#   by length and first put the shortest. Totally unperfect decision so feel free to propose better one
#
# String literals looks like
#> .LCXX:
#>  .string "some string literal inside double quotes"
# and then can be yet several - I willfully decided to skip such long strings
#> .string "continuation of very long string"
# and finally
#> .align D
#
# functions headers:
#> .type   mangled_function_name, %function
#
# function ends with
#> .cfi_endproc
#
# and inside functions we should look for pairs of instructions
#> adrp    x0, .LCXX
#> add     x0, x0, :lo12:.LCXX
# then if LCXX is AND of all conditions
# 1) reffered only from one function
# 2) is real string literal
# 3) .cfi_endproc even with already added strings has size < 2048 bytes
# we can
#  * replace this pair (so reduce code size on 4 byte) with
#>> adr x0, .LCXX
#  * mark original string definition and removed
#  * put it before .cfi_endproc in .text section
#  * inc size of function for length of moved string + 1
# Amen
use strict;
use warnings;
use Carp;
use Getopt::Std;

use vars qw/$opt_D $opt_d $opt_f $opt_l $opt_v/;
# main restriction on size of function
my $g_limit = 2048;

sub HELP_MESSAGE()
{
  printf STDERR<<EOF;
Usage: $0 [options] file1.S ...
Options:
 -D - hardcore debug
 -d - make debug dumps
 -f - dump functions
 -l - dump literals
 -v - verbose mode
EOF
  exit(8);
}

# file.s read logic
# object is just ref to array with indexes
# 0 - fh
# 1 - filename
# 2 - ref to array with file content
# 3 - ref to hash with LC, key - label name
# 4 - ref to functions hash, key - function name
sub make_fobj
{
  my $fn = shift;
  my($fh, @res, %l_c, %f_h);
  if ( !open($fh, '<', $fn) )
  {
    carp("cannot open $fn");
    return undef;
  }
  return [ $fh, $fn, \@res, \%l_c, \%f_h ];
}

# fixme - there are probably others sections for literal constants
sub is_rsection {
  my $sn = shift;
  # for sections like rodata.something
  return 1 if ( $sn =~ /^\.rodata\./ );
  return 1 if ( $sn eq '.rodata' or $sn eq '.init.rodata' );
  return 0;
}

# each stored string is array where indexes
# 0 - state
# 1 - for instructions inside function - offset from start
# 2 - string itself
sub put_string {
  my($fobj, $str) = @_;
  my $aref = $fobj->[2];
  push @$aref, [ 0, -1, $str ];
}

sub put_instr {
  my($fobj, $str, $i) = @_;
  my $aref = $fobj->[2];
  push @$aref, [ 0, $i, $str ];
}

# add some const literal
# params: fobj, name, start line number, end line number
sub add_label {
 my($fobj, $l_name, $l_num, $l_end) = @_;
 my $lh = $fobj->[3];
 my %fr;
 $lh->{$l_name} = [ $l_num, $l_end, \%fr ];
}

sub add_lref {
 my($fobj, $lname, $fname) = @_;
 my $lh = $fobj->[3];
 return if ( !exists $lh->{$lname} );
 my $fx = $lh->{$lname}->[2];
 $fx->{$fname} = 1;
}

sub dump_labels {
  my $fobj = shift;
  my $lh = $fobj->[3];
  while( my ($key, $value) = each %$lh) {
   my $rsize = scalar keys %{ $value->[2] };
   printf("%s: %d refs\n", $key, $rsize);
   # dump refs to this label
   if ( $rsize )
   {
     foreach my $who ( keys %{ $value->[2] } ) {
       printf(" xref from %s\n", $who);
     }
   }
   # dump body
   for ( my $i = $value->[0]; $i < $value->[1]; $i++ ) {
     printf(" %d: %s\n", $i, $fobj->[2]->[$i]->[2]);
   }
  }
}

# mark label for deleting
sub mark_label {
  my($fobj, $lname) = @_;
  my $lh = $fobj->[3];
  if ( !exists( $lh->{$lname} ) )
  {
    carp("no label $lname");
    return 0;
  }
  my $v = $lh->{$lname};
  for ( my $i = $v->[0]; $i < $v->[1]; $i++ )
  { $fobj->[2]->[$i]->[0] = 1; }
  return 1;
}

# each function is array where indexes
# 0 - total xrefs to literal consts
# 1 - size in bytes
# 2 - array of refs
sub add_func {
 my($fobj, $fname) = @_;
 my $fh = $fobj->[4];
 if ( exists $fh->{$fname} )
 {
   carp("duplicated function $fname");
   return undef;
 }
 my $r = [ 0, 0, [] ];
 $fh->{$fname} = $r;
 return $r;
}

sub dump_funcs {
 my $fobj = shift;
 my $fh = $fobj->[4];
 while( my ($key, $value) = each %$fh) {
   printf("func %s has size %X bytes %d refs\n", $key, $value->[1], $value->[0]);
   next if ( !$value->[0] );
   my $xr = $value->[2];
   foreach my $iter ( @$xr )
   {
     printf(" at line %d reg %s -> %s\n", $iter->[0], $iter->[1], $iter->[2]);
   }
 }
}

# add xref inside function
sub put_xref {
 my($fdata, $fx_line, $fx_reg, $fx_name) = @_;
 my $ar = $fdata->[2];
 $fdata->[0]++;
 push @$ar, [ $fx_line, $fx_reg, $fx_name ];
};

sub dump_patch
{
  my($fobj, $chext) = @_;
  my $fname = $fobj->[1];
  $fname =~ s/\.s$/\.sp/ if ( $chext );
  my($fh, $str);
    if ( !open($fh, '>', $fname) )
  {
    carp("cannot create $fname");
    return 0;
  }
  my $arr = $fobj->[2];
  foreach $str ( @{ $arr } )
  {
    printf($fh "%s\n", $str->[2]) if ( !$str->[0] );
  }
  close $fh;
  return 1;
}

# read whole .s file content and fill LC constants in fobj->[3]
sub read_s
{
  my $fobj = shift;
  my $res = 0;
  my($str, $func_name, $l_name, $l_num, $fdata);
  my $state = 0;
  my $in_rs = 0;
  my $fh = $fobj->[0];
  my $line = 0;
  my $pc = 0;
  my $l_state = 0;
  my $f_state = 0;
  # xref data
  my($fx_line, $fx_reg, $fx_name);
  while( $str = <$fh> )
  {
    chomp $str; $line++;
    if ( $str =~ /^\s*\.section\s+(\.?[\.\w]+)/ )
    {
      $state = $l_state = 0;
      $in_rs = is_rsection($1);
      put_string($fobj, $str); next;
    }
    if ( $str =~ /^\s*\.text/ )
    {
      add_label($fobj, $l_name, $l_num, $line - 1) if ( $l_state == 2 );
      $in_rs = $state = $l_state = 0;
      put_string($fobj, $str); next;
    }
    # try to extract const literal
    if ( $in_rs )
    {
      put_string($fobj, $str);
      if ( $str =~ /^\s*(\.LC\S+):/ )
      {
        add_label($fobj, $l_name, $l_num, $line - 1) if ( $l_state == 2 );
        $l_name = $1;
        $l_state = 1;
        $l_num = $line - 1;
# printf("label %s at %d %s\n", $l_name, $l_num, $fobj->[2]->[$l_num]->[2]) if defined($opt_D);
        next;
      } elsif ( $l_state && $str =~ /^\s+\.string\s+\"/ )
      {
        # allow only .string directive
        if ( $l_state == 1 ) { $l_state = 2; }
        else { $l_state = 0; }
# printf("string state %d line %d\n", $l_state, $line - 1) if defined($opt_D);
      } elsif ( $l_state == 2 ) {
        add_label($fobj, $l_name, $l_num, $line - 1);
        $l_state = 0;
      }
      next;
    }
    if ( $str =~ /^\s*\.type\s+(\S+), \%function/ )
    {
      $in_rs = $pc = $f_state = 0;
      $func_name = $1;
      $state = 1;
      $fdata = add_func($fobj, $func_name);
      put_string($fobj, $str); next;
    }
    # if we alreay inside function ?
    if ( $state )
    {
      if ( $str =~ /^\s*\.cfi_endproc/ )
      {
        $state = 0;
        if ( defined $fdata ) { $fdata->[1] = $pc * 4; }
# printf("%s pc %X\n", $func_name, $pc) if defined($opt_d);
        put_string($fobj, $str); next;
      }
      # skip labels
      if ( $str =~ /:$/ )
      { put_string($fobj, $str); next; }
      # skip any directives
      if ( $str =~ /^\s+\./ )
      { put_string($fobj, $str); next; }
      # yep, this is some instruction
      put_instr($fobj, $str, $pc); $pc += 4;
      if ( defined $fdata ) {
        # check for adrp reg, label
        if ( $str =~ /^\s*adrp\s+(\w+),\s*(\S+)$/ )
        {
          $l_state = 1;
          $fx_line = $line - 1;
          $fx_reg = $1;
          $fx_name = $2;
          add_lref($fobj, $fx_name, $func_name);
          next;
        }
        if ( $l_state )
        {
          $l_state = 0;
          # check for add reg, reg, :lo12:label
          next if ( $str !~ /^\s*add\s+(\w+),\s*(\w+),\s*:lo12:(\S+)$/ );
          my $dreg = $1;
          next if ( $dreg ne $2 );
          next if ( $dreg ne $fx_reg );
          next if ( $3 ne $fx_name );
# printf("%s refs to %s\n", $func_name, $fx_name);
          put_xref($fdata, $fx_line, $fx_reg, $fx_name);
          $res++;
        }
      }
      next;
    }
    put_string($fobj, $str);
  }
  # close file
  close $fh;
  $fobj->[0] = undef;
  return $res;
}

# main workhorse
sub apatch {
 my $fobj = shift;
 return 0;
}

### main
my $status = getopts("Ddflv");
HELP_MESSAGE() if ( !$status );
HELP_MESSAGE() if ( $#ARGV == -1 );
# process all files
foreach my $fname ( @ARGV )
{
  printf("process %s\n", $fname) if defined($opt_v);
  my $fobj = make_fobj($fname);
  next if !defined($fobj);
  my $res = read_s($fobj);
  printf("%d functions, %d xrefs\n", scalar keys %{ $fobj->[4] }, $res) if defined($opt_v);
  dump_labels($fobj) if ( defined($opt_l) );
  dump_funcs($fobj) if ( defined($opt_f) );
  dump_patch($fobj, 1) if ( defined($opt_D) );
  if ( $res )
  {
    dump_patch($fobj, 0) if apatch($fobj);
  }
}