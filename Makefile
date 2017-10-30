ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

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

