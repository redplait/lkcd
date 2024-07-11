INCLUDE=..

all: bmc_test

bmc_test: main.cc
	gcc -I $(INCLUDE) $(OUTPUT_OPTION) $< -lbpf

