#!make -f
ELFIO=../../ELFIO
DEBUGOPTS=-g -gdwarf-4

kotest: kotest.cc ../inject/hd.cc
	g++ -Wall $(DEBUGOPTS) -o $@ -I $(ELFIO) $< -lstdc++
