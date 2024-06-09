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
#  * mark original .LCXX definition as removed
#  * move it before .cfi_endproc in .text section
#  * inc size of function for length of moved string + 1
# Amen
# 9 may 2024 (c) redplait
#
# Addition from 12 may 2024
# after playing a bit with gcc optimization settings (like -O2, -Os etc) I noticed 2 weird things:
# 1) compiler can insert some instruction(s) between adrp and following add. It's pure madness to do
#  liveness analysis for .S files, so best we can do - just collect some statistics about such cases
#  and probably make dirty workaround for most frequently encountered instructions (seems that we have
#  absolute champion: mov)
# 2) regs in adrp and add may differs, kinda
#> adrp reg1, .LCXX
#> add reg2, reg1, :lo12:.LCXX
#  Here we could patch to adr reg2, .LCXX only if those two are adjacent, bcs else can happens something like
#> adrp reg1, .LCXX
#> mov reg2, reg3 or any other instruction(s) used reg3
#> add ref3, reg1, :lo12:.LCXX
# Since all these methods are extremely unreliable I add -m option for them
#
# also bcs now all moved string don't merging by ld they have duplicates (and increase overall size of binary)
# to mitigate this I add couple options for filtering functions to patch:
# -F filename with functions names
# -s - section name (for example in lkm .init.text etc)
#
# Addition from 9 jun 2024
# mips (option -M) has literal constants in form
#> $LC0:
#>     .ascii  "const string %f\012\000"
# and without sizes
# function ends with
#> .end
# also like x86 you can't patch opcodes:
#>    lui     $2,%hi($LCXX)
#>    addiu   $4,$2,%lo($LCXX)
# just move LC into code section

use strict;
use warnings;
use Carp;
use Getopt::Std;

use vars qw/$opt_D $opt_F $opt_d $opt_f $opt_g $opt_i $opt_l $opt_M $opt_m $opt_s $opt_v $opt_w/;
# restriction on offset
my $g_limit = 2048;

sub HELP_MESSAGE()
{
  printf STDERR<<EOF;
Usage: $0 [options] file1.S ...
Options:
 -D - hardcore debug
 -d - make debug dumps
 -F file with list of functions to process
 -f - dump functions
 -g - try all non-global symbols
 -i - x86_64 arch
 -l - dump literals
 -M - mips arch
 -m - try to detect adrp/add pairs even with interleved movs, extremely dangerous
 -s section name
 -v - verbose mode
 -w - don't rewrite original file
EOF
  exit(8);
}

# functions filter
my %g_funcfilter;

sub read_F {
 my $fh;
 if ( !open($fh, '<', $opt_F) ) {
    carp("cannot open file with functions $opt_F");
    return 0;
  }
  my $str;
  while( $str = <$fh> ) {
    chomp $str;
    $g_funcfilter{ $str }++;
  }
  close $fh;
  1;
}

sub allowed_func {
 my $fname = shift;
 return 1 if ( !defined $opt_F );
 return exists $g_funcfilter{$fname};
};

# global stat for interbed opcodes
my %g_inter;

sub add_bad_opcode {
 my $str = shift;
 return if ( $str !~ /^\s*(\w+)\s/ );
 $g_inter{$1}++;
}

sub dump_bad_opcodes {
 my @tmp;
 while( my ($key, $value) = each %g_inter) {
   push @tmp, [ $key, $value ];
 }
 # sort tmp
 my @sorted = sort { $b->[1] <=> $a->[1] } @tmp;
 foreach ( @sorted )
 {
   printf("bad %s: %d\n", $_->[0], $_->[1]);
 }
}

# check if we know that interbed opcode is safe and don't use dreg
sub check_mov {
 my($str, $dreg) = @_;
 return 0 if ( $str !~ /^\s*mov\s+(.*)$/ );
 foreach ( split(/[\s,]+/, $1) ) {
   return 0 if ( $_ eq $dreg );
 }
 return 1;
}

# file.s read logic
# object is just ref to array with indexes
# 0 - fh
# 1 - filename, used in dump_patch
# 2 - ref to array with file content
# 3 - ref to hash with LC, key - label name, value - see add_label
# 4 - ref to functions hash, key - function name, value - see add_func
# 5 - ref to hash of globals, key - name
# 6 - ref to hash of symbols size, key - name, value - number
sub make_fobj
{
  my $fn = shift;
  my($fh, @res, %l_c, %f_h, %g_h, %s_h);
  if ( !open($fh, '<', $fn) )
  {
    carp("cannot open $fn");
    return undef;
  }
  return [ $fh, $fn, \@res, \%l_c, \%f_h, \%g_h, \%s_h ];
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
# 0 - skip line if non-zero
# 1 - for instructions inside function - offset from start, for end of function wnere we add moved parts -2
# 2 - string itself
sub put_string {
  my($fobj, $str) = @_;
  my $aref = $fobj->[2];
  push @$aref, [ 0, -1, $str ];
}

sub put_end_instr {
  my($fobj, $str) = @_;
  my $aref = $fobj->[2];
  push @$aref, [ 0, -2, $str, [] ];
  return $aref->[-1]->[3];
}

sub put_instr {
  my($fobj, $str, $pc) = @_;
  my $aref = $fobj->[2];
  push @$aref, [ 0, $pc, $str ];
}

# add some const literal
# literal is ref to array where indexes
# 0 - start line number
# 1 - end line number
# 2 - ref to xrefs hashmap
# params: fobj, name, start line number, end line number
sub add_label {
 my($fobj, $l_name, $l_num, $l_end) = @_;
 my $lh = $fobj->[3];
 my %xrefs;
 $lh->{$l_name} = [ $l_num, $l_end, \%xrefs ];
}

# store xref from function fname to literal lname
sub add_lref {
 my($fobj, $lname, $fname) = @_;
 my $lh = $fobj->[3];
# printf("add_lref %s %d\n", $lname, exists $lh->{$lname});
 return 0 if ( !exists $lh->{$lname} );
 my $fx = $lh->{$lname}->[2]; # xrefs hashmap
 $fx->{$fname}++;
 1;
}

sub dump_labels {
  my $fobj = shift;
  my $lh = $fobj->[3]; # ref to LC hashmap
  while( my ($key, $value) = each %$lh) {
   my $rsize = scalar keys %{ $value->[2] };
   printf("%s: %d refs\n", $key, $rsize);
   # dump refs to this label
   if ( $rsize ) {
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

# dump moved const literal to file $fh
sub dump_label {
 my($fobj, $fh, $lv) = @_;
 for ( my $i = $lv->[0]; $i < $lv->[1]; $i++ ) {
   printf($fh "%s\n", $fobj->[2]->[$i]->[2]);
 }
}

# mark label lname for deleting
sub mark_label {
  my($fobj, $lname) = @_;
  my $lh = $fobj->[3]; # ref to LC hashmap
  if ( !exists( $lh->{$lname} ) ) {
    carp("no label $lname");
    return undef;
  }
  my $v = $lh->{$lname};
  # check if this label already was disabled - for example by some instruction above
  return undef if ( $fobj->[2]->[ $v->[0] ]->[0] );
  for ( my $i = $v->[0]; $i < $v->[1]; $i++ )
  { $fobj->[2]->[$i]->[0] = 1; }
  return $v;
}

sub allowed_section {
  my $sname = shift;
  return 1 if ( !defined($opt_s) );
  return 0 if ( !defined($sname) );
  return $sname eq $opt_s;
};

# each function is array where indexes
# 0 - total xrefs to literal consts
# 1 - size in bytes
# 2 - array of refs
# 3 - ref to addendum
# 4 - filter flag, 1 if need to process
sub add_func {
 my($fobj, $fname, $sname) = @_;
 my $fh = $fobj->[4];
 if ( exists $fh->{$fname} )
 {
   carp("duplicated function $fname");
   return undef;
 }
 my $allowed = allowed_section($sname) && allowed_func($fname);
 my $r = [ 0, 0, [], undef, $allowed ];
 $fh->{$fname} = $r;
 return $r;
}

# scan function for uniq referred labels and return rh - hash{name} -> ref to label
sub get_uniq {
 my($f, $lh, $rh) = @_;
 return 0 if ( !$f->[0] ); # no refs in this function
 my $res = 0;
 my $xr = $f->[2]; # array of refs
 foreach my $iter ( @$xr )
 {
   next if ( !exists $lh->{$iter->[2]} );
   # check that this label has ref count = 1
   my $lv = $lh->{$iter->[2]};
   my $rsize = scalar keys %{ $lv->[2] };
   next if ( $rsize != 1 );
   # cool, store ref to literal in rh
   $res++;
   $rh->{ $iter->[2] } = $lv;
 }
 return $res;
}

# move label to addendum of func
# returns (size in bytes of patched opcodes, 1 if label was really moved)
sub move_label {
  my($fobj, $func, $label) = @_;
  my $lv = mark_label($fobj, $label);
  my $xr = $func->[2]; # array of refs
  my $dec = 0;
  my $moved = 0;
  foreach my $iter ( @$xr ) {
    next if ( $iter->[2] ne $label );
    if ( defined($opt_i) || defined($opt_M) ) { # don't patch leaq - it's already in right format
      # $fobj->[2]->[$iter->[0]]->[2] = sprintf("\tleaq %s(%%rip), %s", $iter->[2], $iter->[1]);
      $dec += 1;
    } else { # aarch64 patch
      # patch adrp to adr
      $fobj->[2]->[$iter->[0]]->[2] = sprintf("\tadr %s, %s", $iter->[1], $iter->[2]);
      # disable string with add, line number $iter->[4]
      $fobj->[2]->[$iter->[4]]->[0] = 1;
      $dec += 4;
    }
  }
  # finally put $lv to addendum of this func if need to
  if ( defined $lv ) {
    my $add = $func->[3];
    push @$add, $lv;
    $moved = 1;
  }
  return ($dec, $moved);
}

# fill hash with minimal offsets of corresponding adrp
# return count of found offsets
sub extract_offsets {
 my($func, $u_ref, $res) = @_;
 my $xr = $func->[2]; # array of refs
 my $rcount = 0;
 foreach my $iter ( @$xr ) {
   next if ( !exists $u_ref->{$iter->[2]} );
   next if ( exists $res->{$iter->[2]} );
   $res->{$iter->[2]} = $iter->[3];
   $rcount++;
 }
 return $rcount;
}

# get length of const literal, very weak version - I just return length of whole "string"
sub extract_len {
 my($fobj, $lv, $lname) = @_;
 my $sh = $fobj->[6];
 # consult first in sizes map
 return $sh->{$lname} if ( exists $sh->{$lname} );
 # ok, iterate body of this label to find .string directive
 for ( my $i = $lv->[0]; $i < $lv->[1]; $i++ ) {
   my $str = $fobj->[2]->[$i]->[2];
   return 1 + length($1) if ( $str =~ /^\s+\.string\s+\"(.*)\"$/ );
   return 1 + length($1) if ( $str =~ /^\s+\.ascii\s+\"(.*)\"$/ );
 }
 return undef;
}

sub dump_funcs {
 my $fobj = shift;
 my $fh = $fobj->[4];
 my $gh = $fobj->[5];
 while( my ($key, $value) = each %$fh) {
   next if ( !$value->[0] && !defined($opt_v) );
   printf("func %s has size %X bytes %d refs\n", $key, $value->[1], $value->[0]);
   next if ( !$value->[0] );
   my $xr = $value->[2];
   foreach my $iter ( @$xr ) {
     next if ( defined($opt_g) && exists $gh->{ $iter->[2] } );
     printf(" at line %d pc %X reg %s -> %s\n", $iter->[0], $iter->[3], $iter->[1], $iter->[2]);
   }
 }
}

# add xref inside function
# xref is array where indexes are
# 0 - line number so you can access string itself and pc
# 1 - target reg
# 2 - label name
# 3 - pc - used in extract_offsets
# 4 - line number of corresponding add
sub put_xref {
 my($fdata, $fx_line, $fx_reg, $fx_name, $pc, $add_line) = @_;
 my $ar = $fdata->[2];
 $fdata->[0]++;
 push @$ar, [ $fx_line, $fx_reg, $fx_name, $pc, $add_line ];
};

# common method for damping results, can be used for debug purposes too
sub dump_patch
{
  my($fobj, $rewrite) = @_;
  my $fname = $fobj->[1];
  $fname =~ s/\.s$/\.sp/ if ( !$rewrite );
  my($fh, $str);
    if ( !open($fh, '>', $fname) ) {
    carp("cannot create $fname");
    return 0;
  }
  my $arr = $fobj->[2];
  foreach $str ( @{ $arr } )
  {
    my $put_align = 0;
    next if ( $str->[0] );
    if ( -2 == $str->[1] ) { # dump addendum before .cfi_endproc
      my $ar = $str->[3];
      if ( defined $ar ) {
        foreach my $ml ( @$ar ) {
          dump_label($fobj, $fh, $ml);
        }
        $put_align = 1 if ( scalar @$ar );
      }
    }
    printf($fh "\t.align 2\n") if ( $put_align );
    printf($fh "%s\n", $str->[2]);
  }
  close $fh;
  return 1;
}

sub rm_globals {
 my $fobj = shift;
 return if ( !defined $opt_g );
 my $gh = $fobj->[5];
 my $sh = $fobj->[6];
 my $lh = $fobj->[3];
 foreach ( keys %$gh ) {
   delete $sh->{$_};
   delete $lh->{$_};
 }
}

# read whole .s file content and fill LC constants in fobj->[3]
sub read_s
{
  my $fobj = shift;
  my $fh = $fobj->[0];
  my $gh = $fobj->[5];
  my $sh = $fobj->[6];
  my $res = 0;
  my($str, $func_name, $section, $l_name, $l_num, $fdata);
  my $state = 0;
  my $in_rs = 0;
  my $line = 0;
  my $pc = 0;
  my $l_state = 0;
  # xref data
  my($fx_line, $fx_reg, $fx_name, $fx_pc);
  # perl's way to make macro
  my $check_lc = sub {
   add_label($fobj, $l_name, $l_num, $line - 1) if ( $l_state == 2 );
   $l_state = 0;
  };
  while( $str = <$fh> )
  {
    chomp $str; $line++;
    if ( $str =~ /^\s*\.section\s+(\.?[\.\w]+)/ )
    {
      $check_lc->();
      $state = 0;
      $section = $1;
# printf("section %s\n", $section);
      $in_rs = is_rsection($section);
      put_string($fobj, $str); next;
    }
    if ( $str =~ /^\s*\.text/ )
    {
      $check_lc->();
      $in_rs = $state = 0;
      $section = ".text";
      put_string($fobj, $str); next;
    }
    if ( $str =~ /^\s*\.rdata/ )
    {
      $check_lc->();
      $state = 0;
      $section = '.rdata';
      $in_rs = 1;
      put_string($fobj, $str); next;
    }
    # .size
    if ( $str =~ /^\s*\.size\s+(\S+)\s*,\s*(\d+)$/ ) {
      $sh->{$1} = int($2);
      put_string($fobj, $str); next;
    }
    # .global
    if ( defined($opt_g) && $str =~ /^\s*\.globa?l\s+(\S+)$/ ) {
      $gh->{$1}++;
      put_string($fobj, $str); next;
    }
    # try to extract const literal
    if ( $in_rs )
    {
      put_string($fobj, $str);
      # check if this is some label
      if ( defined($opt_g) && $str =~ /^\s*(\S+):$/ ) {
        $check_lc->();
        $l_name = $1;
        $l_state = 1;
        $l_num = $line - 1;
        next;
      }
      if ( $str =~ /^\s*([\.\$]LC\S+):/ )
      {
        $check_lc->();
        $l_name = $1;
        $l_state = 1;
        $l_num = $line - 1;
# printf("label %s at %d %s\n", $l_name, $l_num, $fobj->[2]->[$l_num]->[2]) if defined($opt_D);
        next;
      } elsif ( $l_state && $str =~ /^\s+\.string\s+\"/ )
      {
        # allow .string directive
        if ( $l_state == 1 ) { $l_state = 2; }
        else { $l_state = 0; }
# printf("string state %d line %d\n", $l_state, $line - 1) if defined($opt_D);
      } elsif ( $l_state && $str =~ /^\s+\.ascii\s+\"/ )
      {
        # allow .ascii directive
        if ( $l_state == 1 ) { $l_state = 2; }
        else { $l_state = 0; }
      } else {
        $check_lc->();
      }
      next;
    }
    if ( $str =~ /^\s*\.type\s+(\S+), [\%@]function/ )
    {
      $in_rs = $pc = 0;
      $func_name = $1;
      $state = 1;
      $fdata = add_func($fobj, $func_name, $section);
      put_string($fobj, $str); next;
    }
    # if we alreay inside function ?
    if ( $state )
    {
      if ( $str =~ /^\s*\.cfi_endproc/ or
           (defined($opt_M) && $str =~ /^\s*\.end/ )
         )
      {
        $state = $l_state = 0;
        if ( defined $fdata ) {
          $fdata->[1] = $pc; # store function size
          $fdata->[3] = put_end_instr($fobj, $str);
          next;
        }
# printf("%s pc %X\n", $func_name, $pc) if defined($opt_d);
        put_string($fobj, $str); next;
      }
      # skip labels - reset l_state
      if ( $str =~ /:$/ )
      { put_string($fobj, $str); $l_state = 0; next; }
      # skip any directives
      if ( $str =~ /^\s+\./ )
      { put_string($fobj, $str); next; }
      # yep, this is some instruction
      put_instr($fobj, $str, $pc); $pc += 4;
      if ( defined $fdata ) {
        if ( defined $opt_i ) { # for x86_64 scan leaq LC(%rip), %dest_reg
          if ( $str =~ /^\s*leaq\s+(\S+)\(\%rip\),\s*(\S+)$/ )
          {
            $fx_line = $line - 1;
            $fx_reg = $2;
            $fx_name = $1;
            add_lref($fobj, $fx_name, $func_name);
            put_xref($fdata, $fx_line, $fx_reg, $fx_name, $pc - 4, $fx_line) if ( $fdata->[4] );
            $res++;
          }
          next;
        }
        if ( defined($opt_M) ) {
          if ( $str =~ /^\s*lui\s+(\S+)\,\%hi\((\S+)\)$/ )
          {
            $fx_line = $line - 1;
            $fx_reg = $1;
            $fx_name = $2;
            add_lref($fobj, $fx_name, $func_name);
            put_xref($fdata, $fx_line, $fx_reg, $fx_name, $pc - 4, $fx_line) if ( $fdata->[4] );
            $res++;
          }
          next;
        }
        # check for adrp reg, label
        if ( $str =~ /^\s*adrp\s+(\w+),\s*(\S+)$/ )
        {
          $l_state = 1;
          $fx_line = $line - 1;
          $fx_reg = $1;
          $fx_name = $2;
          $fx_pc = $pc - 4;
          add_lref($fobj, $fx_name, $func_name);
          next;
        }
        if ( $l_state )
        {
          $l_state = 0;
          # check for add reg, reg, :lo12:label
          if ( $str !~ /^\s*add\s+(\w+),\s*(\w+),\s*:lo12:(\S+)$/ ) {
            add_bad_opcode($str);
            $l_state = 1 if ( defined($opt_m) && check_mov($str, $fx_reg) );
            next;
          }
          next if ( $fx_reg ne $2 );  # second reg in add must be the same as first in adrp
          next if ( $3 ne $fx_name ); # symbol must be the same
          my $dreg = $1;
          if ( $dreg ne $fx_reg )     # if add happens to other register
          {
            next if ( !defined $opt_m );
            next if ( $line - 2 != $fx_line ); # check that adrp & add are adjacent
            $fx_reg = $dreg;
          }
# printf("%s refs to %s\n", $func_name, $fx_name);
          put_xref($fdata, $fx_line, $fx_reg, $fx_name, $fx_pc, $line - 1) if ( $fdata->[4] );
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
 my $fh = $fobj->[4];
 my $lh = $fobj->[3];
 my $res = 0;
 # iterate for all functions
 while( my ($key, $value) = each %$fh) {
   next if ( !$value->[4] ); # skip filtered functions
   my %uniq;
   next if ( !get_uniq($value, $lh, \%uniq) );
   if ( defined($opt_v) ) {
     printf("func %s:\n", $key);
     foreach my $rname ( keys %uniq ) {
       printf(" %s\n", $rname);
     }
   }
   # extract size for each label, if can't - put labels name in no_size for deleting from uniq
   my(@as, @no_size);
   while( my($name, $lv) = each %uniq ) {
     my $rsize = extract_len($fobj, $lv, $name);
     if ( !defined $rsize ) {
# printf("name %s no rsize\n", $name);
       push @no_size, $name;
       next;
     }
     push @as, [ $name, $rsize]; # index 0 - name, 1 - size
   }
   # remove from uniq useless labels without size
   foreach ( @no_size ) { delete $uniq{$_}; }
   # sort labels by sizes
   my @size_sorted =  @as;
   if ( defined($opt_v ) ) {
     foreach my $rname ( @size_sorted ) {
       printf("%s size %d\n", $rname->[0], $rname->[1]);
     }
   }
   # extract minimal offsets of corresponding adrp for label xrefs
   my %moffs;
   extract_offsets($value, \%uniq, \%moffs);
   my $curr_fsize = $value->[1];
   # patch by 1 - sadly O(N * M) where N is number of labels and M is number of xrefs in this function
   foreach my $rname ( @size_sorted ) {
     # check that we can access this const literal
     next if ( ! exists $moffs{$rname->[0]} );
     my $curr_moff = $moffs{$rname->[0]};
     if ( !defined($opt_i) && !defined($opt_M) ) {
       my $diff = $curr_fsize - $curr_moff;
       if ( $diff > $g_limit ) {
         printf("skip %s bcs diff %X is too high, curr_size %X, off %X\n", $rname->[0], $diff, $curr_fsize, $curr_moff);
         next;
       }
     }
     # bcs we eliminate 1 add instruction - whole size of function can be decreased
     # probably this could make possible to return early rejected xrefs but it's too tedious to rescan
     my($dec, $moved) = move_label($fobj, $value, $rname->[0]);
# printf("dec %d moved %d\n", $dec, $moved);
     $curr_fsize += $rname->[1] if ( $moved );
     if ( $dec ) {
       $curr_fsize -= $dec;
       $res++;
       # Optimization: fix moffs located below currently processed - dec their offsets by $dec
       while ( my($mname, $moff) = each %moffs ) {
         next if ( $moff <= $curr_moff );
         $moffs{$mname} -= $dec;
       }
     }
   }
 }
 return $res;
}

### main
my $status = getopts("DdfgilMmvwF:s:");
HELP_MESSAGE() if ( !$status );
HELP_MESSAGE() if ( $#ARGV == -1 );
exit(2) if ( defined($opt_F) && !read_F() );
# process all files
foreach my $fname ( @ARGV )
{
  printf("process %s\n", $fname) if defined($opt_v);
  my $fobj = make_fobj($fname);
  next if !defined($fobj);
  my $res = read_s($fobj);
  rm_globals($fobj);
  printf("%d functions, %d xrefs\n", scalar keys %{ $fobj->[4] }, $res) if defined($opt_v);
  if ( defined($opt_l) ) {
    dump_labels($fobj);
    # dump size
    my $sh = $fobj->[6];
    while( my ($name, $sz) = each %$sh) {
     printf(" %s size %d\n", $name, $sz);
    }
  }
  dump_funcs($fobj) if ( defined($opt_f) );
  dump_patch($fobj, 0) if ( defined($opt_D) );
  if ( $res )
  {
    my $rewrite = 1;
    $rewrite = 0 if ( defined $opt_w );
    my $patched = apatch($fobj);
    if ( $patched ) {
      dump_patch($fobj, $rewrite);
      printf("patched %d ops\n", $patched) if ( defined($opt_v) );
    }
  }
}
# dump bad opcodes
dump_bad_opcodes() if ( defined($opt_v) );
