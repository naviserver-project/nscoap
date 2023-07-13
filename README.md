# README #

# Usage:
Start NaviServer with the sample config in one window in the foreground:

````
$ /usr/local/ns/bin/nsd -t nscoap-config.tcl -f
````

The sample config file maps GET and POST requests to /foo/* for
forwarding to the HTTP server. The sample config file registers as
well a request handler for POST and GET on /foo/bar via
`ns_register_proc`. One can certainly run other requests by adding
tcl/adp/html files into the pages directory, or via other means
possible by NaviServer.

To issue a CoAP GET request from other terminal, one can use e.g. the
wget like coap-client from https://github.com/obgm/libcoap.git:

````
$ coap-client -m get coap://localhost/foo/bar
GET-okidoki
````

Issue a CoAP POST request (assuming, you have
a file called TODO in your current directory):

````
$ coap-client -m post -f TODO coap://localhost/foo/bar
POST-okidoki(961)
````

The number between parens is the number of bytes transferred in
body of the POST request (check the registered proc in the
sample config file `nscoap-config.tcl`.

When issuing these requests, the terminal running the server in the
foreground shows some debugging information prefixed with
`Debug(coap)`.  This output can be controlled e.g. in the config file
via `ns_logctl severity Debug(coap) on|off`.
