ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Program name
#
PGM     = nscoap

#
# Objects to build.
#
PGMOBJS = nscoap.o

include $(NAVISERVER)/include/Makefile.module

