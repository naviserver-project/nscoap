ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

NSD             = $(NAVISERVER)/bin/nsd
NS_TEST_CFG     = -c -d -t tests/config.tcl -u nsadmin
NS_TEST_ALL     = all.tcl $(TESTFLAGS)
LD_LIBRARY_PATH = LD_LIBRARY_PATH="./:$$LD_LIBRARY_PATH"

#
# Program name
#
MOD     = nscoap.so

#
# Objects to build.
#
MODOBJS = nscoap.o
HDRS    = nscoap.h

include $(NAVISERVER)/include/Makefile.module


test: all
	export $(LD_LIBRARY_PATH); $(NSD) $(NS_TEST_CFG) $(NS_TEST_ALL)
