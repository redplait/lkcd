INCLUDE=..

all: ntfytest

ntfytest.o: ntfytest.c
	$(COMPILE.c) -I $(INCLUDE) $(OUTPUT_OPTION) $<

ntfytest: ntfytest.o
	gcc -o $@ -I $(INCLUDE) $^
