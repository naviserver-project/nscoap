/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * The Initial Developer of the Original Code and related documentation
 * is America Online, Inc. Portions created by AOL are Copyright (C) 1999
 * America Online, Inc. All Rights Reserved.
 */

/*
 * nscoap.c -- CoAP-to-HTTP proxy driver
 *
 *
 * Usage:
 *
 *   Configure in the NaviServer config file:
 *
 *   ###############################################
 *   ...
 *   ns_section    ns/servers/server/modules
 *   ns_param      nscoap        nscoap.so
 *
 *   ns_section    ns/servers/server/module/nscoap
 *   ns_param      address    ::1
 *   ns_param      port       5683
 *   ...
 *   ###############################################
 *
 *
 * To send coap packages, use:
 *
 *   ns_coap ?-timeout N? ?-noreply? ipaddr port data
 *
 *      ns_coap ::1 "GET / HTTP/1.0\r\n\r\n"
 *
 * Authors
 *
 *     David Hopfmüller <david@hopfmueller.at>
 *     based on the nsudp module by Vlad Seryakov <vlad@crystalballinc.com>
 */

#include "nscoap.h"

NS_EXPORT int Ns_ModuleVersion = 1;
NS_EXPORT Ns_ModuleInitProc Ns_ModuleInit;

#define NSCOAP_ARRAY_NAME "nscoap"

/*
 * Static functions defined in this file.
 */
static Ns_ReturnCode ParseHttp(Packet_t *packet, HttpRep_t *http);
static bool CheckRemainingSize(Packet_t *packet, size_t increment);
static void CoapSentError(Ns_Sock *sock, size_t len);
static bool SerializeHttp(HttpReq_t *http, Tcl_DString *dsPtr);
static byte Http2CoapCode(unsigned int http);
static const char *CoapMethodCodeToString(unsigned int codeValue);
static const char *CoapContentFormatToString(unsigned int contentFormat);

static TCL_OBJCMDPROC_T CoapObjCmd;
static Ns_DriverSendProc Send;

/*
 * Static variables defined in this file.
 */
static Ns_LogSeverity Ns_LogCoapDebug;
static Tcl_Encoding UTF8_Encoding = NULL;
static int coapKey = -1;

/*
 * Function Definitions
 */

# if 1
static void hexPrint(const char *msg, const unsigned char *octets, size_t octetLength, const char *string)
{
    size_t i;
    fprintf(stderr, "%s (len %zu): ", msg, octetLength);
    for (i=0; i<octetLength; i++) {
        fprintf(stderr, "%.2x ", octets[i] & 0xff);
    }
    if (string != NULL) {
        fprintf(stderr, "'%s'", string);
    }
    fprintf(stderr, "\n");
}
# endif


NS_EXPORT Ns_ReturnCode Ns_ModuleInit(const char *server, const char *module)
{
    const char        *path;
    CoapDriver        *drvPtr;
    Ns_DriverInitData  init;
    const Ns_Set      *lset;

    path = Ns_ConfigGetPath(server, module, (char *)0);
    drvPtr = ns_calloc(1, sizeof(CoapDriver));

    /*
     * Perform the following initialization only once, even when loading the
     * driver multiple times for different addresses or ports.
     */
    if (coapKey < 0) {
        coapKey = Ns_UrlSpecificAlloc();

        UTF8_Encoding = Tcl_GetEncoding(NULL, "utf-8");
    }

    Ns_Log(Notice, "ModuleInit: path <%s>", path);
    lset = Ns_ConfigGetSection(path);

    if (lset != NULL && Ns_SetSize(lset) > 0u) {
        /*
         * The configuration has a driver module section, which is not empty.
         */
        size_t      j;
        Tcl_DString ds, *dsPtr = &ds;

        Tcl_DStringInit(dsPtr);
        for (j = 0u; j < Ns_SetSize(lset); ++j) {
            const char *key = Ns_SetKey(lset, j);

            if (STREQ(key, "mapHTTP")) {
                const char *p, *urlSpec = Ns_SetValue(lset, j);

                /*
                 * We found a mapHTTP spec. The spec has to contain the HTTP
                 * method followed by a space and the URL pattern. The
                 * specified HTTP method is checked for sanity to be less than
                 * 100 chars.
                 */
                p = strchr(urlSpec, INTCHAR(' '));
                if (p != NULL) {
                    ssize_t methodNameLength = (p - urlSpec);

                    if (methodNameLength < 100) {
                        char method[100];

                        memcpy(method, urlSpec, (size_t)methodNameLength);
                        method[methodNameLength] = '\0';
                        Ns_UrlSpecificSet(server, method, p+1, coapKey, INT2PTR(1), 0u, NULL);
                        Ns_Log(Notice, "nscoap: map HTTP method <%s> url <%s>", method, p+1);
                    } else {
                        Ns_Log(Warning, "nscoap mapHTTP: method name is too log in spec: '%s>'", urlSpec);
                    }
                } else {
                    Ns_Log(Warning, "nscoap mapHTTP: invalid spec: '%s>'", urlSpec);
                }
            }
        }
    }

    /*
     * Initialize the driver structure.
     */
    memset(&init, 0, sizeof(init));
    init.version = NS_DRIVER_VERSION_4;
    init.name = "nscoap";
    init.listenProc = Listen;
    init.acceptProc = Accept;
    init.recvProc = Recv;
    init.requestProc = NULL;
    init.sendProc = Send;
    init.sendFileProc = NULL;
    init.keepProc = Keep;
    init.closeProc = Close;
    init.opts = NS_DRIVER_ASYNC|NS_DRIVER_UDP;
    init.arg = drvPtr;
    init.path = path;
    init.protocol = "udp";
    init.defaultPort = 5683;

    Ns_LogCoapDebug = Ns_CreateLogSeverity("Debug(coap)");

    Ns_TclRegisterTrace(server, CoapInterpInit, drvPtr, NS_TCL_TRACE_CREATE);
    Ns_Log(Notice, "nscoap: version %s loaded", NSCOAP_VERSION);

    return Ns_DriverInit(server, module, &init);
}

static int
CoapInterpInit(Tcl_Interp *interp, const void *arg)
{
    TCL_CREATEOBJCOMMAND(interp, "ns_coap", CoapObjCmd, (ClientData)arg, NULL);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Listen --
 *
 *      Open a listening UDP socket in nonblocking mode.
 *
 * Results:
 *      The open socket or NS_INVALID_SOCKET on error.
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */

static NS_SOCKET
Listen(Ns_Driver *UNUSED(driver), const char *address, unsigned short port, int UNUSED(backlog), bool reuseport)
{
    NS_SOCKET sock;

    sock = Ns_SockListenUdp((char*)address, port, reuseport);
    if (sock != NS_INVALID_SOCKET) {
        (void) Ns_SockSetNonBlocking(sock);
    }
    return sock;
}


/*
 *----------------------------------------------------------------------
 *
 * Accept --
 *
 *      Accept a new UDP socket in nonblocking mode.
 *
 * Results:
 *      NS_DRIVER_ACCEPT_DATA  - socket accepted, data present
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static NS_DRIVER_ACCEPT_STATUS
Accept(Ns_Sock *sock, NS_SOCKET listensock,
       struct sockaddr *UNUSED(saPtr), socklen_t *UNUSED(socklenPtr))
{
    sock->sock = listensock;

    return NS_DRIVER_ACCEPT_DATA;
}


/*
 *----------------------------------------------------------------------
 *
 * Recv --
 *
 *      Receive data into given buffers.
 *
 * Results:
 *      Total number of bytes received or -1 on error or timeout.
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */

static ssize_t
Recv(Ns_Sock *sock, struct iovec *bufs, int nbufs,
     Ns_Time *UNUSED(timeoutPtr), unsigned int UNUSED(flags))
{
    CoapMsg_t        coap;
    CoapParams_t    *cp = sock->arg;
    ssize_t          msgSize;
    socklen_t        socklen = (socklen_t)sizeof(struct NS_SOCKADDR_STORAGE);
    struct sockaddr *saPtr = (struct sockaddr *)&(sock->sa);

    msgSize = recvfrom(sock->sock, bufs->iov_base, bufs->iov_len, 0,
                       saPtr, &socklen);
    Ns_LogSockaddr(Ns_LogCoapDebug, "Recv", saPtr);
    Ns_Log(Ns_LogCoapDebug, "Recv sock %d socken %u msgSize %lu nbufs %d bufSize %lu",
           sock->sock, socklen, msgSize, nbufs, bufs->iov_len);

    if (msgSize > 0) {
        Packet_t pin;

        pin.raw  = bufs->iov_base;
        pin.size = (size_t)msgSize;
        pin.position = 0u;

        if (cp == NULL) {
            cp = ns_calloc(1u, sizeof(CoapParams_t));
            sock->arg = cp;
            Ns_Log(Ns_LogCoapDebug, "Recv: create new sock params %p", (void*)cp);
        } else {
            Ns_Log(Ns_LogCoapDebug, "Recv: reuse sock params %p", (void*)cp);
        }
        memset(&coap, 0, sizeof(coap));

        if (ParseCoap(&pin, &coap, cp)) {
            size_t i;
            bool   mapHTTP = NS_FALSE;
            size_t keyLength;
            char   key[13] = "";

            for (i = 0u; i < (size_t)coap.optionCount; i++) {
                /*fprintf(stderr, "coap.options[%zd] = %d\n", i, coap.options[i]->number);*/
                if (coap.options[i]->number == 11
                    && coap.options[i]->length < 13) {
                    keyLength = coap.options[i]->length;
                    memcpy(key, coap.options[i]->value, keyLength);
                    key[keyLength] = 0u;

                    if (Ns_LogSeverityEnabled(Ns_LogCoapDebug)) {
                        hexPrint("key:", (unsigned char*)key, keyLength, key);
                    }

                    /*
                     * Try the lookup from the URL-trie for all values except a
                     * first URI path option of "nsv".
                     */
                    if ((strcmp(key, "nsv") != 0)
                        && coap.options[i]->delta > 0
                        ) {
                        void *mapResult = Ns_UrlSpecificGet(
#if NS_VERSION_NUM >= 50000
                                                            Ns_GetServer(sock->driver->server),
#else
                                                            sock->driver->server,
#endif
                                                            CoapMethodCodeToString(coap.codeValue),
                                                            key,
                                                            coapKey
#if NS_VERSION_NUM >= 50000
                                                            ,0u, NS_URLSPACE_FAST, NULL, NULL, NULL
#endif
                                                            );
                        mapHTTP = mapResult != NULL;
                        Ns_Log(Ns_LogCoapDebug, "Recv: coap server %s: option[%lu] type %.6x <%s> mapHTTP-> %d",
                               sock->driver->server, i, coap.type, key, mapHTTP);
                    } else if (coap.options[i]->delta == 0) {
                        break;
                    }
                }
            }

            Ns_Log(Ns_LogCoapDebug, "Recv: parsed coap %" PRIdz " bytes #options %u map to HTTP %d",
                   msgSize, coap.optionCount, (int)mapHTTP);

            if (mapHTTP) {
                Tcl_DString ds;
                HttpReq_t   httpRequest;

                memset(&httpRequest, 0, sizeof(httpRequest));

                Tcl_DStringInit(&ds);
                if (Coap2Http(&coap, &httpRequest)
                    && SerializeHttp(&httpRequest, &ds)
                    ) {
                    /*
                     * Pass content to HTTP backend
                     */
                    Ns_Log(Ns_LogCoapDebug, "Recv: overwrite receive buffer old length %lu new length %lu",
                           bufs->iov_len, (unsigned long)ds.length);
                    /*
                     * Make sure that we can indeed copy the content to this
                     * buffer without globbering memory.
                     */
                    assert(bufs->iov_len > (size_t)ds.length);

                    memcpy(bufs->iov_base, ds.string, (size_t)ds.length);
                    msgSize = (ssize_t)ds.length;
                    Ns_Log(Ns_LogCoapDebug, "Recv: passed to HTTP backend; processed %" PRIdz " bytes", msgSize);
                } else {
                    Ns_Log(Error, "Recv: could not parse coap to HTTP");
                    msgSize = -1;
                }
                Tcl_DStringFree(&ds);

            } else {
                CoapMsg_t   coapReply;
                ssize_t     sentBytes;
                HttpRep_t   httpReply;
                Packet_t    pout;
                byte        buffer[MAX_PACKET_SIZE];
                Tcl_DString ds, *dsPtr = NULL;

                /*
                 * In case we have a "key" set, try to look up the key from
                 * the shared NSCOAP_ARRAY_NAME. This allows a light-way
                 * reporting of a sensor, which might update the nsv
                 * periodically. It does not require the full HTTP round trip.
                 */
                httpReply.payload = NULL;
                if (key[0] != 0u) {
                    dsPtr = &ds;

                    Tcl_DStringInit(dsPtr);
                    if (Ns_VarGet(sock->driver->server, NSCOAP_ARRAY_NAME, key, dsPtr) == NS_OK) {
                        httpReply.status = 200;
                        httpReply.payload = (byte *)dsPtr->string;
                        httpReply.payloadLength = (size_t)dsPtr->length;
                        Ns_Log(Ns_LogCoapDebug, "Reply: lookup of nscoap array returned '%s'", dsPtr->string);
                    } else {
                        Ns_Log(Ns_LogCoapDebug, "Reply: lookup of nscoap array for key <%s> failed", key);
                        httpReply.payloadLength = 0u;
                        httpReply.status = 404;
                    }

                } else {
                    /*
                     * If no URI path is set, respond directly (evaluation mode).
                     */
                    httpReply.payload = (byte *)"OK";
                    httpReply.payloadLength = 2;
                    httpReply.status = 200;
                }

                Http2Coap(&httpReply, &coapReply, cp);

                pout.raw = buffer;
                SerializeCoap(&coapReply, &pout);

                sentBytes = sendto(sock->sock, pout.raw, pout.size, 0,
                                   saPtr, Ns_SockaddrGetSockLen(saPtr));

                if (sentBytes == -1) {
                    CoapSentError(sock, pout.size);
                } else {
                    Ns_Log(Ns_LogCoapDebug, "Reply: sent %" PRIdz " bytes cp %p", sentBytes, (void*)cp);
                }

                if (dsPtr != NULL) {
                    Tcl_DStringFree(dsPtr);
                }

                /*
                 * The driver does not have to handle to handle the data, all
                 * replies are already done here. So flag this via msgSize.
                 */
                cp->flags |= NSCOAP_FLAG_ALREADY_HANDLED;
                //msgSize = 0;
                msgSize = -1;

            }
        } else {
            Ns_Log(Warning, "Recv: could not parse coap package");
            msgSize = -1;
        }
    } else {
        Ns_Log(Ns_LogCoapDebug, "Recv: finished; no data received");
    }

    return msgSize;
}


/*
 *----------------------------------------------------------------------
 *
 * Send --
 *
 *      Send data from given buffers.
 *
 * Results:
 *      Total number of bytes sent or -1 on error or timeout.
 *
 * Side effects:
 *      May block once for driver sendwait timeout seconds if first
 *      attempt would block.
 *
 *----------------------------------------------------------------------
 */

static ssize_t
Send(Ns_Sock *sock, const struct iovec *bufs, int nbufs,
#if NS_MAJOR_VERSION < 5
     const Ns_Time *UNUSED(timeoutPtr),
#endif
     unsigned int UNUSED(flags))
{
    int           nbuf;
    ssize_t       size;
    CoapParams_t *cp = sock->arg;
    Tcl_DString  *inbuf = cp->sendbuf;

    //Ns_Log(Ns_LogCoapDebug, "Send %d", sock->sock);

    if (inbuf == NULL) {
        inbuf = ns_calloc(1u, sizeof(Tcl_DString));
        Tcl_DStringInit(inbuf);
        cp->sendbuf = inbuf;
    }

    /* Append buffer content to sendbuf */
    for (nbuf = 0, size = 0; nbuf < nbufs; nbuf++) {
        Tcl_DStringAppend(inbuf, bufs[nbuf].iov_base, (int)bufs[nbuf].iov_len);
        size += (ssize_t)bufs[nbuf].iov_len;
    }

    Ns_Log(Ns_LogCoapDebug, "Send (%d): finished; received %ld bytes, total of %lu bytes buffered",
           sock->sock, size, (unsigned long)inbuf->length);
    return size;
}


/*
 *----------------------------------------------------------------------
 *
 * Keep --
 *
 *      Keep-alive handling make no sense with UDP.
 *
 * Results:
 *      NS_FALSE, always.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static bool
Keep(Ns_Sock *UNUSED(sock))
{
    return NS_FALSE;
}


/*
 *----------------------------------------------------------------------
 *
 * Close --
 *
 *      Close the connection socket.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Sends the remainder of the buffer. It Does not close UDP socket (since
 *      there is nothing to close).
 *
 *----------------------------------------------------------------------
 */

static void
Close(Ns_Sock *sock)
{
    CoapParams_t *cp = sock->arg;

    Ns_Log(Ns_LogCoapDebug, "Close (%d): cp %p sendbuf %p flags %.6x", sock->sock, (void*)cp,
           cp != NULL ? (void*)cp->sendbuf : NULL,
           cp != NULL ? cp->flags : 0x0u);

    if (cp == NULL) {
        Ns_Log(Warning, "Close: missing coap socket args");
    } else if (cp->sendbuf == NULL) {
        Ns_Log(Ns_LogCoapDebug, "Close: empty send buffer");

    } else {
        CoapMsg_t        coap;
        HttpRep_t        http;
        Packet_t         pin, pout;
        Tcl_DString     *sendbuf;
        byte             buffer[MAX_PACKET_SIZE];
        struct sockaddr *saPtr = (struct sockaddr *)&(sock->sa);

        memset(&coap, 0, sizeof(coap));
        memset(&http, 0, sizeof(http));

        Ns_LogSockaddr(Ns_LogCoapDebug, "Close", saPtr);

        sendbuf = cp->sendbuf;

        pin.size = (size_t)sendbuf->length;
        pin.position = 0u;
        pin.raw = (byte *)sendbuf->string;

        pout.size = 0u;
        pout.position = 0u;
        pout.raw = buffer;

        if (ParseHttp(&pin, &http) != NS_OK
            || !Http2Coap(&http, &coap, cp)
            || !SerializeCoap(&coap, &pout)) {
            Ns_Log(Error, "Close: exiting; proxy/parse failed, nothing sent");
        } else {
            ssize_t sentBytes;

            sentBytes = sendto(sock->sock, pout.raw, (size_t)pout.size, 0,
                               saPtr, Ns_SockaddrGetSockLen(saPtr));
            if (sentBytes == -1) {
                CoapSentError(sock, pout.size);
            } else {
                Ns_Log(Ns_LogCoapDebug, "Close: sent %" PRIdz " bytes", sentBytes);
            }
        }

        /*
         * Clear the send buffer, but do not free the Tcl_DString structure in
         * cp, since we might want to reuse it.
         */
        Tcl_DStringFree(sendbuf);
    }
    //sock->arg = NULL;
    Ns_Log(Ns_LogCoapDebug, "Close (%d) invalidates socket", sock->sock);
    sock->sock = NS_INVALID_SOCKET;

    return;
}


static int
CoapObjCmd(ClientData UNUSED(clientData), Tcl_Interp *interp, TCL_SIZE_T objc, Tcl_Obj *const* objv)
{
    fd_set         fds;
    unsigned char  buf[16384];
    struct timeval tv;
    Tcl_DString    ds;
    Tcl_Obj       *objd;
    unsigned char *data;
    struct NS_SOCKADDR_STORAGE sa, ba;
    struct sockaddr
        *saPtr = (struct sockaddr *)&sa,
        *baPtr = (struct sockaddr *)&ba;
    char          *address = NULL, *bindaddr = NULL;
    int            sock, rc = TCL_OK, stream = 0, timeout = 5, retries = 1, noreply = 0;
    TCL_SIZE_T     i, intlen;
    unsigned short port;
    ssize_t        len;
    Ns_ObjvSpec opts[] = {
        {"-timeout",  Ns_ObjvInt,    &timeout,  NULL},
        {"-noreply",  Ns_ObjvBool,   &noreply,  (void*)1},
        {"-retries",  Ns_ObjvInt,    &retries,  NULL},
        {"-stream",   Ns_ObjvInt,    &stream,   NULL},
        {"-bind",     Ns_ObjvString, &bindaddr, NULL},
        {"--",        Ns_ObjvBreak,  NULL,      NULL},
        {NULL, NULL, NULL, NULL}
    };
    Ns_ObjvSpec args[] = {
        {"address",  Ns_ObjvString, &address, NULL},
        {"port",     Ns_ObjvInt,    &port,    NULL},
        {"data",     Ns_ObjvObj,    &objd,    NULL},
        {NULL, NULL, NULL, NULL}
    };

    if (Ns_ParseObjv(opts, args, interp, 1, objc, objv) != NS_OK) {
      return TCL_ERROR;
    }

    if (Ns_GetSockAddr(saPtr, address, port) != NS_OK) {
        sprintf((char*)buf, "%s:%d", address, port);
        Tcl_AppendResult(interp, "invalid address ", buf, 0);
        return TCL_ERROR;
    }

    sock = socket(saPtr->sa_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        Tcl_AppendResult(interp, "socket error ", strerror(errno), 0);
        return TCL_ERROR;
    }
    /* To support brodcasting addresses */
    i = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &i, sizeof(int));

    /* Bind to local address */
    if (bindaddr != NULL && Ns_GetSockAddr(baPtr, bindaddr, 0) == NS_OK) {
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(int));
        if (bind(sock, baPtr, Ns_SockaddrGetSockLen(baPtr)) != 0) {
            Tcl_AppendResult(interp, "bind error ", strerror(errno), 0);
            ns_sockclose(sock);
            return TCL_ERROR;
        }
    }

    data = Tcl_GetByteArrayFromObj(objd, &intlen);
    len = (ssize_t)intlen;

resend:
    {
        char saString[NS_IPADDR_SIZE], baString[NS_IPADDR_SIZE];

        Ns_Log(Ns_LogCoapDebug, "nscoap: sending %" PRIdz " bytes to [%s]:%d from %s", len,
               ns_inet_ntop(saPtr, saString, sizeof(saString)),
               Ns_SockaddrGetPort(saPtr),
               ns_inet_ntop(baPtr, baString, sizeof(baString)));
    }

    if (sendto(sock, data, (size_t)len, 0, saPtr, Ns_SockaddrGetSockLen(saPtr)) < 0) {
        Tcl_AppendResult(interp, "sendto error ", strerror(errno), 0);
        ns_sockclose(sock);
        return TCL_ERROR;
    }
    if (noreply) {
        ns_sockclose(sock);
        return TCL_OK;
    }
    memset(buf,0,sizeof(buf));
    Ns_SockSetNonBlocking(sock);
    Tcl_DStringInit(&ds);
    do {
       FD_ZERO(&fds);
       FD_SET(sock,&fds);
       tv.tv_sec = timeout;
       tv.tv_usec = 0;
       len = select(sock+1, &fds, 0, 0, &tv);
       switch (len) {
        case -1:
            if (errno == EINTR || errno == EINPROGRESS || errno == EAGAIN) {
                continue;
            }
            Tcl_DStringSetLength(&ds, 0);
            Ns_DStringPrintf(&ds, "select error %s", strerror(errno));
            rc = TCL_ERROR;
            goto done;

        case 0:
            if (stream) {
                goto done;
            }
            if(--retries < 0) {
               goto resend;
            }
            Tcl_DStringSetLength(&ds, 0);
            Ns_DStringPrintf(&ds, "timeout");
            rc = TCL_ERROR;
            goto done;
       }
       if (FD_ISSET(sock, &fds)) {
           socklen_t socklen = Ns_SockaddrGetSockLen(saPtr);
           len = recvfrom(sock, buf, sizeof(buf)-1, 0, saPtr, &socklen);
           if (len > 0) {
               Tcl_DStringAppend(&ds, (char*)buf, (int)len);
           }
       }
    } while (stream);
done:
    ns_sockclose(sock);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char*)ds.string, ds.length));
    Tcl_DStringFree(&ds);
    return rc;
}


/*
 * Check size of the CoAP message
 *
 * Returns a boolean value indicating whether the remaining size >= increment.
 */
static bool CheckRemainingSize(Packet_t *packet, size_t increment)
{
    bool success;

    if ((packet->position + increment) > packet->size) {
        success = NS_FALSE;
    } else {
        success = NS_TRUE;
    }

    return success;
}


/*
 * Parse the content of a CoAP packet into a CoAP object.
 *
 * Returns a boolean value indicating success.
 */
static bool ParseCoap(Packet_t *packet, CoapMsg_t *coap, CoapParams_t *params) {
    Option_t    *optionPtr;
    size_t       i;
    unsigned int codeValue, lastOptionNumber = 0u;
    bool         processOptions;
    Code_t       code;

    /* Registry of valid CoAP message codes */
    static const unsigned int code_registry[] = {
        000, 001, 002, 003, 004,
        201, 202, 203, 204, 205,
        400, 401, 402, 403, 404, 405, 406, 412, 413, 415,
        500, 501, 502, 503, 504, 505
    };

    packet->position = 0;
    coap->valid = NS_TRUE;

    Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: packet length: %lu", packet->size);
    /* CoAP messages can't be shorter than 4 bytes */
    if (CheckRemainingSize(packet, 4u) == NS_FALSE) {
        Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: message shorter than 4 bytes");
        return NS_FALSE;
    }

    /* Bit 0-1: CoAP version: Must be 0b01 */
    coap->version = ((packet->raw[0] >> 6) == 0x1u);
    Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: version %d", coap->version);
    if (coap->version == 0) {
        coap->valid = NS_FALSE;
        return NS_FALSE;
    }

    /* Bit 2-3: Type of CoAP message */
    coap->type = ((packet->raw[0] >> 4) & 0x3u);
    params->type = coap->type;
    Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: message type: %d", coap->type);

    /* Bit 4-7: Token Length */
    coap->tokenLength = (packet->raw[0] & 0x0fu);
    Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: token length: %d", (int)coap->tokenLength);

    if (coap->tokenLength > 8) {
        coap->valid = NS_FALSE;
        return NS_FALSE;
    }

    /* Bit 8-15: Message Code */
    code.class  = ((packet->raw[1] >> 5) & 0x7u);
    code.detail = (packet->raw[1] & 0x1fu);
    codeValue   = code.class * 100u + code.detail;
    Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: message code: %d", codeValue);

    /*
     * Check, if the code belongs to the codes defined by the CoAP RFC.  If
     * not, we report the request being not valid (which might be a little
     * harsh for some applications).
     */
    for (i = 0u; i < (sizeof(code_registry) / sizeof(int)); i++) {
        if (code_registry[i] == codeValue) {
            coap->codeValue = codeValue;
            break;
        }
    }
    if (coap->codeValue == 0) {
        return NS_FALSE;
    }

    /* Bit 16-31: Message ID */
    coap->messageID = ((unsigned int) packet->raw[2] << 8) + (unsigned int) packet->raw[3];
    params->messageID = coap->messageID;
    Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: messageID: %d", coap->messageID);

    /* Bit 32ff: Token */
    packet->position = 4;
    if (coap->tokenLength > 0) {
        if (CheckRemainingSize(packet, coap->tokenLength) == NS_TRUE) {
            memcpy(coap->token, &(packet->raw[4]), coap->tokenLength);
            memcpy(params->token, coap->token, coap->tokenLength);
            params->tokenLength = coap->tokenLength;
            packet->position += coap->tokenLength;
            Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: valid token found");
        } else {
            return NS_FALSE;
        }
    }

    /*
     * Options. Option Numbers are maintained in the "CoAP Option Numbers"
     * registry.
     */
    processOptions = CheckRemainingSize(packet, 1u);

    while (processOptions) {
        /*
         * Option Bits:
         *    0-3: Option Delta
         *    4-7: Option Length
         *    8-15: Option Delta extended (8 bit,  when delta is 0x0d)
         *    8-23: Option Delta extended (16 bit, when delta is 0x0e)
         *    Option Length extended (8 bit, when length is 0x0d; 16 bit, when length is 0x0e)
         *    Option Value
         */
        optionPtr = ns_malloc(sizeof(Option_t));

        optionPtr->delta = ((packet->raw[packet->position] >> 4) & 0x0fu);
        optionPtr->length = (packet->raw[packet->position] & 0x0fu);
        optionPtr->value = NULL;

        packet->position++;
        Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: processing option: delta %u, length %u, count %d",
               optionPtr->delta, optionPtr->length, coap->optionCount);

        /* Parse option delta */
        switch (optionPtr->delta) {
        case 0x0fu:
            /* Payload marker or invalid */
            switch (optionPtr->length) {
            case 0x0fu:
                    coap->payload = &(packet->raw[packet->position]);
                    coap->payloadLength = packet->size - packet->position;
                    Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: payload marker detected. Payload length = %lu",
                           coap->payloadLength);
                    break;
            default:
                    coap->valid = NS_FALSE;
                    break;
            }
            processOptions = NS_FALSE;
            break;

        case 0x0eu:
            if (CheckRemainingSize(packet, 2u) == NS_TRUE) {
                optionPtr->delta =
                    ((unsigned int) packet->raw[packet->position] << 8) +
                    ((unsigned int) packet->raw[packet->position + 1] + 269);
                packet->position += 2;
            }
            break;

        case 0x0du:
            if (CheckRemainingSize(packet, 1u) == NS_TRUE) {
                optionPtr->delta = ((unsigned int) packet->raw[packet->position] + 13);
                packet->position += 1;
            }
            break;

        default:
            break;
        }

        /* No payload, process length */
        if (processOptions) {
            optionPtr->number = optionPtr->delta + lastOptionNumber;
            lastOptionNumber = optionPtr->number;
            //Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: final option number = %u", optionPtr->number);
            switch (optionPtr->length) {
            case 0x0fu:
                coap->valid = NS_FALSE;
                processOptions = NS_FALSE;
                break;

            case 0x0eu:
                if (CheckRemainingSize(packet, 2u) == NS_TRUE) {
                    optionPtr->length =
                        ((unsigned int)packet->raw[packet->position] << 8) +
                        ((unsigned int)packet->raw[packet->position + 1] + 269);
                    packet->position += 2;
                }
                break;

            case 0x0du:
                if (CheckRemainingSize(packet, 1u) == NS_TRUE) {
                    optionPtr->length = ((unsigned int)packet->raw[packet->position] + 13);
                    packet->position += 1;
                }
                break;

            default:
                break;
            }
            //Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: final option length = %u", optionPtr->length);
        }

        if (processOptions) {
            if (optionPtr->length > 0) {
                if (CheckRemainingSize(packet, optionPtr->length) == NS_TRUE) {
                    optionPtr->value = &(packet->raw[packet->position]);
                    packet->position += optionPtr->length;
                } else {
                    coap->valid = NS_FALSE;
                    processOptions = NS_FALSE;
                }
            }
        }
        if (processOptions) {

            /*
             * Append option to collection
             */
            coap->options[coap->optionCount++] = optionPtr;
            Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: added option %d to collection", optionPtr->number);

            if (CheckRemainingSize(packet, 1u) == NS_FALSE) {
                Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: no further options/payload");
                processOptions = NS_FALSE;
            }
        }
        Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: finished parsing option/payload");
    }

    return coap->valid;
}


/*
 *----------------------------------------------------------------------
 *
 * CoapMethodCodeToString --
 *
 *      Perform a mapping from the CoAP method code to the HTTP
 *      string notation.
 *
 * Results:
 *      const string or NULL, if it does not succeed.
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */
static const char *
CoapMethodCodeToString(unsigned int codeValue) {
    const char *result;
    /*
     * Method codes:
     *   CoAP supports the following methods which are a subset of those
     *   supported by HTTP
     */
    static const char *methods[] = {
            "",
            "GET",
            "POST",
            "PUT",
            "DELETE"
    };

    if (codeValue < 5) {
        result = methods[codeValue];
    } else {
        result = NULL;
    }
    return result;
}


/*
 *----------------------------------------------------------------------
 *
 * CoapContentFormatToString --
 *
 *      Perform a mapping from the CoAP content format code to the HTTP
 *      string notation.
 *
 * Results:
 *      const string, maybe using "text/plain" as fallback
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */
static const char *
CoapContentFormatToString(unsigned int contentFormat) {
    const char *result;

    if (contentFormat == 0) {
        result = "text/plain;charset=utf-8";
    } else if (contentFormat == 40) {
        result = "application/link-format";
    } else if (contentFormat == 41) {
        result = "application/xml";
    } else if (contentFormat == 42) {
        result = "application/octet-stream";
    } else if (contentFormat == 47) {
        result = "application/exi";
    } else if (contentFormat == 50) {
        result = "application/json";
    } else if (contentFormat == 60) {
        result = "application/cbor";
    } else if (contentFormat == 61) {
        result = "application/cwt";
    } else {
        result = "text/plain;charset=utf-8";
        Ns_Log(Notice, "coap: unknown content format %d, fall back to: %s", contentFormat, result);
    }
    return result;
}


/*
 * Translate CoAP parameters to HTTP.
 *
 * Returns a boolean value indicating success.
 */
static bool Coap2Http(CoapMsg_t *coap, HttpReq_t *http) {
    bool       success = NS_TRUE;
    int        opt;
    char       uutoken[17];
    size_t     uutokenLength;
    Tcl_DString rawval, *rawvalPtr = &rawval;
    Tcl_DString urlenc, *urlencPtr = &urlenc;

    /*
     * Token
     *   Since the CoAP token consists of 'raw' bytes we need to encode it.
     *   UUencode is available, so let's use it.
     */
    Tcl_DStringInit(&http->token);
    uutokenLength = Ns_HtuuEncode(coap->token, coap->tokenLength, uutoken);
    Tcl_DStringAppend(&http->token, uutoken, (int)uutokenLength);

    http->method = CoapMethodCodeToString(coap->codeValue);

    /* Process CoAP options */
    Tcl_DStringInit(&http->host);
    Tcl_DStringInit(&http->path);
    Tcl_DStringInit(&http->query);

    for (opt = 0; opt < coap->optionCount; opt++) {
        Option_t  *optionPtr = coap->options[opt];

        Tcl_DStringInit(rawvalPtr);
        Tcl_DStringInit(urlencPtr);

        /*
         * URI options:
         *
         * [nr]  [name]
         *    3  URI host
         *    7  URI port
         *   11  URI path
         *   15  URI query
         */
        if (optionPtr->number & 0x3u) {
            Tcl_DStringAppend(rawvalPtr,
                              (char *)(optionPtr->value),
                              (int)optionPtr->length);
            if (optionPtr->number < 4) {
                /* Hosts are not being transcoded from UTF-8 to %-encoding yet (method missing) */
                Tcl_DStringAppend(&http->host, rawvalPtr->string, rawvalPtr->length);

            } else if (optionPtr->number < 8) {
                Tcl_DStringAppend(&http->host, ":", 1);
                Tcl_DStringAppend(&http->host, rawvalPtr->string, rawvalPtr->length);

            } else if (optionPtr->number < 12) {

                Ns_UrlPathEncode(urlencPtr, rawvalPtr->string, UTF8_Encoding);
                Tcl_DStringAppend(&http->path, "/", 1);
                Tcl_DStringAppend(&http->path, urlencPtr->string, urlencPtr->length);

            } else if (optionPtr->number < 16) {
                if (Tcl_DStringLength(&http->query) == 0) {
                    Tcl_DStringAppend(&http->query, "?", 1);
                } else {
                    Tcl_DStringAppend(&http->query, "&", 1);
                }
                Ns_UrlPathEncode(urlencPtr, rawvalPtr->string, UTF8_Encoding);
                Tcl_DStringAppend(&http->query, urlencPtr->string, urlencPtr->length);
            } else {
                Ns_Log(Warning, "nscoap: option %d not handled", optionPtr->number);
            }
        } else if (optionPtr->number == 12) {
            if (optionPtr->length == 1) {
                coap->contentFormat = optionPtr->value[0];
            } else if (optionPtr->length == 2) {
                coap->contentFormat = ((optionPtr->value[0] << 8) & optionPtr->value[1]);
            }
        }
    }

    if (coap->payloadLength > 0u) {
        http->payload       = coap->payload;
        http->payloadLength = coap->payloadLength;
    }
    http->contentType = CoapContentFormatToString(coap->contentFormat);

    Ns_Log(Ns_LogCoapDebug, "Coap2Http: finished; processed %d CoAP options", coap->optionCount);
    return success;
}


/*
 * Translate an HTTP reply object to a CoAP object
 *
 * Returns a boolean value indicating success.
 */
static bool Http2Coap(HttpRep_t *http, CoapMsg_t *coap, CoapParams_t *params)
{
    bool success = NS_TRUE;

    /*
     * Consider conserved CoAP request parameter
     */
    if (params->tokenLength > 0) {
        memcpy(coap->token, params->token, params->tokenLength);
        coap->tokenLength = params->tokenLength;
    } else {
        coap->tokenLength = 0;
    }
    /*
     * Request is of type CON, reply with ACK
     */
    if (params->type == 0) {
        coap->type = 2;
    } else {
        coap->type = 1;
    }
    /*
     * Matching messageID required for piggybacked ACK replies,
     * not forbidden for other replies
     */
    coap->version       = 1;
    coap->codeValue     = http->status;
    coap->messageID     = params->messageID;
    coap->payload       = http->payload;
    coap->payloadLength = http->payloadLength;
    coap->optionCount   = 0;

    Ns_Log(Ns_LogCoapDebug, "Http2Coap: finished; HTTP status: %u", http->status);

    return success;
}


/*
 * Construct an HTTP request from an HTTP object.
 *
 * Returns a boolean value indicating success.
 */
static bool SerializeHttp(HttpReq_t *http, Tcl_DString *dsPtr)
{
    Ns_DStringPrintf(dsPtr, "%s %s%s %s\r\n",
                     http->method, http->path.string,
                     http->query.string, HTTP_VERSION);
    // Ns_DStringPrintf(dsPtr, "Host: %s\n", http->host.string);
    Ns_DStringPrintf(dsPtr, "content-length: %ld\r\n", http->payloadLength);
    if (http->payloadLength > 0) {
        Ns_DStringPrintf(dsPtr, "content-type: %s\r\n\r\n", http->contentType);
        Tcl_DStringAppend(dsPtr, (const char *)http->payload, (int)http->payloadLength);
    } else {
        Tcl_DStringAppend(dsPtr, "\r\n", 2);
    }

    Ns_Log(Ns_LogCoapDebug, "SerializeHttp: finished; HTTP output:\n%s", dsPtr->string);
    return NS_TRUE;
}


static Ns_ReturnCode ParseHttp(Packet_t *packet, HttpRep_t *http)
{
    Ns_ReturnCode status;
    int           returnedStatus;

    Ns_Log(Ns_LogCoapDebug, "ParseHttp started <%s>", packet->raw);

    http->headers = Ns_SetCreate("headers");
#if NS_MAJOR_VERSION > 4
    http->headers->flags |= NS_SET_OPTION_NOCASE;
    status = Ns_HttpResponseMessageParse((char *)packet->raw, (size_t)packet->size,
                                 http->headers,
                                 NULL, NULL,
                                 &returnedStatus,
                                 (char **)&http->payload);
#else
    status = Ns_HttpMessageParse((char *)packet->raw, (size_t)packet->size,
                                 http->headers,
                                 NULL, NULL,
                                 &returnedStatus,
                                 (char **)&http->payload);
#endif
    http->status = (unsigned int)returnedStatus;
    http->payloadLength = (packet->size - (size_t)(http->payload - packet->raw));

    Ns_Log(Ns_LogCoapDebug, "ParseHttp: finished; headers: %d, payload length: %lu, packet size: %lu",
           (int)http->headers->size, http->payloadLength, packet->size);

    return status;
}



/*
 * Construct a CoAP message from a CoAP object.
 */
static bool SerializeCoap(CoapMsg_t *coap, Packet_t *packet) {
    int           o;
    size_t        pos;
    unsigned int  delta, pdelta = 0u;

    /* Mandatory headers */
    packet->raw[0] = (byte)((coap->version << 6) |
                            (coap->type << 4) |
                            (coap->tokenLength));
    packet->raw[1] = Http2CoapCode(coap->codeValue);
    packet->raw[2] = (byte)((coap->messageID >> 8) & 0xffu);
    packet->raw[3] = (byte)(coap->messageID & 0xffu);
    memcpy(&packet->raw[4], coap->token, (size_t)coap->tokenLength);
    pos = (4u + coap->tokenLength);

    /* Options */
    for (o = 0; o < coap->optionCount; o++) {
        Option_t *optionsPtr;
        size_t    dlpos;

        optionsPtr = coap->options[o];
        /* Option code */
        delta = optionsPtr->delta - pdelta;
        pdelta = optionsPtr->delta;
        dlpos = pos++;
        if (delta > 268) {
            packet->raw[dlpos] = (0xeu << 4);
            delta -= 269;
            memcpy(&packet->raw[pos], &delta, 2);
            pos += 2;
        } else if (delta > 12) {
            packet->raw[dlpos] = (0xdu << 4);
            delta -= 13;
            memcpy(&packet->raw[pos], &delta, 1);
            pos += 1u;
        } else {
            packet->raw[dlpos] = (byte)(delta << 4);
        }
        /* Option length */
        if (optionsPtr->length > 268) {
            packet->raw[dlpos] |= 0xeu;
            delta -= 269;
            memcpy(&packet->raw[pos], &optionsPtr->length, 2);
            pos += 2u;
        } else if (optionsPtr->length > 12) {
            packet->raw[dlpos] |= 0xdu;
            delta -= 13;
            memcpy(&packet->raw[pos], &optionsPtr->length, 1);
            pos += 1u;
        } else {
            packet->raw[dlpos] |= ((byte)(optionsPtr->length & (byte)0x0fu));
        }
    }

    /* Payload marker + payload */
    if (coap->payloadLength > 0) {
        size_t maxlen;

        packet->raw[pos++] = 0xffu;
        maxlen = MAX_COAP_SIZE - pos;
        maxlen = coap->payloadLength > maxlen ? maxlen : coap->payloadLength;
        memcpy(&(packet->raw[pos]), coap->payload, (size_t)maxlen);
        pos += maxlen;
    }

    packet->size = pos;

    return NS_TRUE;
}


static byte
Http2CoapCode(unsigned int http)
{
    size_t i;
    byte   coap = 0;
    struct code {
        unsigned int http;
        byte coap;
    } codes[] = {
        { 200, 0x45u }
    };

    for (i = 0u; i < sizeof(codes) / sizeof(struct code); i++) {
        if (http == codes[i].http) {
            coap = codes[i].coap;
            break;
        }
    }

    /* If there's no matching entry convert code to CoAP format */
    if (coap == 0u) {
        coap = (byte)(((http / 100 & 0x7u) << 5) |
                      (http % 100 & 0x1fu));
    }

    return coap;
}


/*
 *----------------------------------------------------------------------
 *
 * CoapSentError --
 *
 *      Send data from given buffers.
 *
 * Results:
 *      Total number of bytes sent or -1 on error or timeout.
 *
 * Side effects:
 *      May block once for driver sendwait timeout seconds if first
 *      attempt would block.
 *
 *----------------------------------------------------------------------
 */
static void CoapSentError(Ns_Sock *sock, size_t len)
{
    char             ipString[NS_IPADDR_SIZE];
    struct sockaddr *saPtr = (struct sockaddr *)&(sock->sa);

    Ns_Log(Error, "nscoap: send operation on FD %d bytes %lu to %s lead to: %s",
           sock->sock, len,
           ns_inet_ntop(saPtr, ipString, sizeof(ipString)),
           strerror(errno));
    /*
     * TODO: probably, we have to cleanup sock...
     */
}
/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
/* vim: set et ts=4 sw=4: */
