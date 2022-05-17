#!perl -w
# dirty script to generate loongson extension
# 16 may 2022 (c) redplait
use strict;
use warnings;

# where is Grail located
my $g_binutil = "D:/src/binutils-gdb/opcodes/mips-opc.c";
# array of names
my @g_names;
# hash of used names
my %g_used;
# main horror. key is mask, value is array [ name, value, string ]
my %g_masks;

sub add_name
{
  my $name = shift;
  return if exists $g_used{$name};
  $g_used{$name}++;
  push @g_names, $name;
}

sub dump_header
{
print<<EOF;
// this file was generated with script data/loong.pl
// do not edit it
EOF
}

sub dump_enum
{
  printf("enum loong_insn_type_t {\n");
  my $id = 0;
  foreach my $n ( @g_names )
  {
    if ( !$id )
    {
      printf(" LOONG_%s = CUSTOM_INSN_ITYPE,\n", $n);
      $id++;
    } else {
      printf(" LOONG_%s,\n", $n);
    }
  }
  printf("};\n\n");
}

sub dump_opnames
{
  printf("const char *loong_op_names[] = {\n");
  foreach my $n ( @g_names )
  {
    printf(" \"%s\", /* LOONG_%s */\n", $n, $n);
  }
  printf("};\n\n");  
}

sub read_missed
{
  my($fn, $hr) = @_;
  my($fp, $str);
  open($fp, '<', $fn) or die("cannot open $fn, error $!\n");
  while( $str = <$fp>)
  {
    chomp $str;
    $hr->{$str}++;
  }
  close $fp;
}

sub read_binutils
{
  my $hr = shift;
  my($fp, $str, %out_h);
  open($fp, '<', $g_binutil) or die("cannot open $g_binutil, error $!\n");
  while( $str = <$fp>)
  {
    chomp $str;
                      #   op name 1          format 2       value 3         mask 4
    next if ( $str !~ /^\{\"([^\"]+)\",\s*\"([^\"]+)\",\s*0x([0-9a-f]+),\s*0x([0-9a-f]+)/ );
    my $name = $1;
    next if ! exists $hr->{$name};
    my $fmt = $2;
    my $value = hex($3);
    my $mask = hex($4);
    add_name($name);
# printf("%s %s %X %X\n", $name, $fmt, $value, $mask);
    if ( exists $g_masks{$mask} )
    {
      my $ar = $g_masks{$mask};
      push @$ar, [ $name, $value, $fmt];
    } else {
      my @ar;
      push @ar, [ $name, $value, $fmt];
      $g_masks{$mask} = \@ar;
    }
  }
}

# main
my %missed;
read_missed("mips.lcam", \%missed);
read_missed("mips.lext", \%missed);
read_missed("mips.lmmi", \%missed);
read_binutils(\%missed);
dump_header();
dump_enum();
dump_opnames();
# dump g_masks
print<<EOF;
int loongson_ana(unsigned long value, insn_t *insn)
{
EOF
foreach my $m ( sort { $b <=> $a } keys %g_masks )
{  
  printf(" switch(value & 0x%X)\n", $m);
  printf(" {\n");
  my $ar = $g_masks{$m};
  foreach my $a ( @$ar )
  {
    printf("  case 0x%X:\n", $a->[1]);
    printf("    insn->itype = LOONG_%s; // %s\n", $a->[0], $a->[2]);
    my $s = $a->[2];
    $s =~ s/\+a\(b\)/plusa/;
    $s =~ s/\+c\(b\)/plusc/;
    $s =~ s/\)//g;
    $s =~ s/\(/,/g;
    $s =~ s/\+/plus/g;
    my $idx = 1;
    foreach my $d ( split /,/, $s )
    {
      printf("    lop_%s(value, insn->Op%d);\n", $d, $idx);
      $idx++;
    }
    printf("  return 4;\n");
  }
  printf(" }\n");  
}
print<<EOF2;
 return 0;
}
EOF2
