#!make -f
ELFIO=../../ELFIO

kotest: kotest.cc ../inject/hd.cc
	g++ -o $@ -I $(ELFIO) $< -lstdc++
