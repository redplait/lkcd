# make -f
ARM64PATH=../../arm64

armtest: armtest.cc arm64thunk.c
	g++ -lstdc++ -o $@ -I $(ARM64PATH) $^ $(ARM64PATH)/libarm64.a

