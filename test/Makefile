INCLUDE=..

all: dtest

kmods.o: kmods.cc

kopts.o: kopts.cc

dtest: dtest.c kmods.o kopts.o
	g++ -lstdc++ -o dtest -I $(INCLUDE) $^
