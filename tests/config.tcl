set homedir [pwd]/tests
set bindir  [file dirname [ns_info nsd]]

ns_section ns/parameters
ns_param   home             $homedir
ns_param   tcllibrary       $bindir/../tcl

ns_section "ns/servers"
ns_param   test            "Test COAP Server"

ns_section ns/server/test/tcl
ns_param   initfile         $bindir/init.tcl

ns_section ns/server/test/modules
ns_param   nscoap           [pwd]/nscoap.so

ns_section   ns/server/test
ns_param     connsperthread 100000  ;# default: 0; number of connections (requests) handled per thread
ns_param     minthreads     2       ;# default: 1; minimal number of connection threads
ns_param     maxthreads     100     ;# default: 10; maximal number of connection threads
ns_param     maxconnections 100     ;# default: 100; number of allocated connection stuctures

ns_section   ns/server/test/module/nscoap
ns_param     address        localhost
ns_param     port           5683
ns_param     mapHTTP       "GET /*"
#ns_param    driverthreads  10          ;# default: 1
#ns_param    acceptsize      1          ;# default: value of "backlog"; max number of accepted (but unqueued) connection requests

# For debugging, you might activate one of the following flags
#
#ns_logctl severity Debug(coap) on
#ns_logctl severity Debug(ns:driver) on
#ns_logctl severity Debug(request) on
