/*
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Copyright (C) 2001-2003 Vlad Seryakov
 * All rights reserved.
 *
 * Alternatively, the contents of this file may be used under the terms
 * of the GNU General Public License (the "GPL"), in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above, a recipient may use your
 * version of this file under either the License or the GPL.
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

static Ns_LogSeverity Ns_LogCoapDebug;


NS_EXPORT int Ns_ModuleInit(const char *server, const char *module)
{
    const char *path;
    CoapDriver *drvPtr;
    Ns_DriverInitData init;

    path = Ns_ConfigGetPath(server, module, (char *)0);
    drvPtr = ns_calloc(1, sizeof(CoapDriver));
    drvPtr->packetsize = Ns_ConfigIntRange(path, "packetsize", -1, -1, INT_MAX);

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

    return Ns_DriverInit(server, module, &init);
}

static int
CoapInterpInit(Tcl_Interp *interp, const void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_coap", CoapObjCmd, (ClientData)arg, NULL);
    Ns_Log(Notice, "nscoap: version %s loaded", NSCOAP_VERSION);
    
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Listen --
 *
 *      Open a listening UDP socket in non-blocking mode.
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
 *      Accept a new TCP socket in non-blocking mode.
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
Recv(Ns_Sock *sock, struct iovec *bufs, int UNUSED(nbufs),
     Ns_Time *UNUSED(timeoutPtr), unsigned int UNUSED(flags))
{
     CoapMsg_t *coap = InitCoapMsg();
     HttpReq_t *http = ns_calloc(1u, sizeof(HttpReq_t));
     Packet_t *pin = ns_calloc(1u, sizeof(Packet_t));
     Packet_t *pout = ns_calloc(1u, sizeof(Packet_t));
     CoapParams_t *cp = sock->arg;
     ssize_t msgsize;
     socklen_t socklen;

     msgsize = recvfrom(sock->sock, pin->raw, bufs->iov_len, 0,
			(struct sockaddr *)&(sock->sa), &socklen);

     /*
      * Provide the actual size of the buffer since the structure is not
      * initialized (no address familiy is known).
      */
     socklen = (socklen_t)sizeof(sock->sa);
     pin->size = (int)msgsize;
     
     if (msgsize > 0) {
         if (cp == NULL) {
             cp = ns_calloc(1u, sizeof(CoapParams_t));
             sock->arg = cp;
         }
	 if (!ParseCoap(pin, coap, cp)
             || !Coap2Http(coap, http)
             || !SerializeHttp(http, pout)) {
             Ns_Log(Error, "Recv: finished; parse/proxy failed");
             return -1;
         }
         memcpy(bufs->iov_base, pout->raw, (size_t)pout->size);
         msgsize = (ssize_t)pout->size;
         Ns_Log(Ns_LogCoapDebug, "Recv: finished; processed %" PRIdz " bytes", msgsize);
     } else {
         Ns_Log(Ns_LogCoapDebug, "Recv: finished; no data received");
     }

     ns_free(coap);
     ns_free(http);
     ns_free(pin);
     ns_free(pout);
     
     return msgsize;
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
     const Ns_Time *UNUSED(timeoutPtr), unsigned int UNUSED(flags))
{
    int nbuf, size;
    CoapParams_t *cp = sock->arg;
    Ns_DString *inbuf = cp->sendbuf;

    /* sock->arg populated by Listen() */
    if (inbuf == NULL) {
        inbuf = ns_calloc(1u, sizeof(Ns_DString));
        Ns_DStringInit(inbuf);
        cp->sendbuf = inbuf;
    }
    
    /* Append buffer content to sendbuf */
    for (nbuf = size = 0; nbuf < nbufs; nbuf++) {
        Tcl_DStringAppend(inbuf, bufs[nbuf].iov_base, (int)bufs[nbuf].iov_len);
        size += bufs[nbuf].iov_len;
    }
    
    Ns_Log(Ns_LogCoapDebug, "Send: finished; received %d bytes, total of %d bytes buffered",
           size, Ns_DStringLength(inbuf));
    return size;
}


/*
 *----------------------------------------------------------------------
 *
 * Keep --
 *
 *      Cannot do keep-alives with UDP
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

    Ns_Log(Ns_LogCoapDebug, "Close %d", sock->sock);
    //{char *p = NULL; *p = 0;}

    if (cp == NULL || cp->sendbuf == NULL) {
        Ns_Log(Ns_LogCoapDebug, "Close: exiting; missing coap socket args or send buffer");
    } else {
        CoapMsg_t  *coap = InitCoapMsg();
        HttpRep_t  *http = ns_calloc(1u, sizeof(HttpRep_t));
        Packet_t   *pin = ns_calloc(1u, sizeof(Packet_t));
        Packet_t   *pout = ns_calloc(1u, sizeof(Packet_t));
        int         plen = 0, sendbuflen = 0;
        Ns_DString *sendbuf;

        sendbuf = cp->sendbuf;
        sendbuflen = Ns_DStringLength(sendbuf);

        /* Continue using reasonable size */
        plen = sendbuflen > MAX_PACKET_SIZE ? MAX_PACKET_SIZE : sendbuflen;
        memcpy(pin->raw, sendbuf->string, plen);
        pin->size = plen;

        if (!ParseHttp(pin, http)
            || !Http2Coap(http, coap, cp)
            || !SerializeCoap(coap, pout)) {
            Ns_Log(Error, "Close: exiting; proxy/parse failed, nothing sent");
        } else {
            ssize_t len;
            struct sockaddr *saPtr = (struct sockaddr *)&(sock->sa);

            len = sendto(sock->sock, pout->raw, (size_t)pout->size, 0,
                         saPtr, Ns_SockaddrGetSockLen(saPtr));
            if (len == -1) {
                char ipString[NS_IPADDR_SIZE];

                Ns_Log(Error, "Close: FD %d: sendto %d bytes to %s: %s",
                       sock->sock, pout->size,
                       ns_inet_ntop(saPtr, ipString, sizeof(ipString)),
                       strerror(errno));
            } else {
                Ns_Log(Ns_LogCoapDebug, "Close: sent %" PRIdz " bytes", len);
            }
        }

        ns_free(coap);
        ns_free(http);
        ns_free(pin);
        ns_free(pout);
        Ns_DStringFree(sendbuf);
    }
    sock->arg = NULL;
    Ns_Log(Ns_LogCoapDebug, "Close sets socket %d to INVALID SOCKET", sock->sock);
    sock->sock = NS_INVALID_SOCKET;

    return;
}


static int
CoapObjCmd(ClientData UNUSED(clientData), Tcl_Interp *interp, int objc, Tcl_Obj *CONST* objv)
{
    fd_set fds;
    unsigned char buf[16384];
    struct timeval tv;
    Tcl_DString ds;
    Tcl_Obj *objd;
    unsigned char *data;
    struct NS_SOCKADDR_STORAGE sa, ba;
    struct sockaddr
        *saPtr = (struct sockaddr *)&sa,
        *baPtr = (struct sockaddr *)&ba;
    char          *address = NULL, *bindaddr = NULL;
    int            i, sock, rc = TCL_OK;
    int            stream = 0, timeout = 5, retries = 1, noreply = 0, intlen;
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
        
        Ns_Log(Notice, "nscoap: sending %" PRIdz " bytes to %s:%d from %s", len,
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
static bool CheckRemainingSize(Packet_t *packet, int increment)
{
    bool success = NS_TRUE;

    if ((packet->position + increment) > packet->size) {
        success = NS_FALSE;
    }

    return success;
}


/*
 * Parse the content of a CoAP packet into a CoAP object.
 *
 * Returns a boolean value indicating success.
 */
static bool ParseCoap(Packet_t *packet, CoapMsg_t *coap, CoapParams_t *params) {
    Option_t   *option;
    int         i, codeValue, lastOptionNumber = 0;
    bool        processOptions;
    Code_t      code;

    /* Registry of valid CoAP message codes */
    static const int code_registry[] = {
        000, 001, 002, 003, 004,
        201, 202, 203, 204, 205,
        400, 401, 402, 403, 404, 405, 406, 412, 413, 415,
        500, 501, 502, 503, 504, 505
    };

    packet->position = 0;
    coap->valid = NS_TRUE;

    Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: packet length: %d", packet->size);
    /* CoAP messages can't be shorter than 4 bytes */
    if (CheckRemainingSize(packet, 4) == NS_FALSE) {
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
    codeValue   = code.class * 100 + code.detail;
    Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: message code: %d", codeValue);
    
    /*
     * Check, if the code belongs to the codes defined by the CoAP RFC.  If
     * not, we report the request being not valid (which might be a little
     * harsh for some applications).
     */
    for (i = 0; i < (sizeof(code_registry) / sizeof(int)); i++) {
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
        if (CheckRemainingSize(packet, (int)coap->tokenLength) == NS_TRUE) {
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
    processOptions = CheckRemainingSize(packet, 1);

    while (processOptions == 1) {
        /*
         * Option Bits:
         *    0-3: Option Delta
         *    4-7: Option Length
         *    8-15: Option Delta extended (8 bit,  when delta is 0x0d)
         *    8-23: Option Delta extended (16 bit, when delta is 0x0e)
         *    Option Length extended (8 bit, when length is 0x0d; 16 bit, when length is 0x0e)
         *    Option Value
         */
        option = ns_malloc(sizeof(Option_t));
        bzero(option, sizeof(Option_t));
        option->delta = ((packet->raw[packet->position] >> 4) & 0x0fu);
        option->length = (packet->raw[packet->position] & 0x0fu);
        packet->position++;
	Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: processing option: number delta = %u, length = %u",
	       option->delta, option->length);

        /* Parse option delta */
        switch (option->delta) {
        case 0x0fu:
		
            /* Payload marker or invalid */
            switch (option->length) {
            case 0x0fu:
		    coap->payload = &(packet->raw[packet->position]);
		    coap->payloadLength = packet->size - packet->position;
		    Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: payload marker detected. Payload length = %d",
			   coap->payloadLength);
		    break;
            default:
		    coap->valid = NS_FALSE;
		    break;
            }
            processOptions = 0;
            break;

        case 0x0eu:
            if (CheckRemainingSize(packet, 2) == NS_TRUE) {
                option->delta =
                    ((unsigned int) packet->raw[packet->position] << 8) +
                    ((unsigned int) packet->raw[packet->position + 1] + 269);
                packet->position += 2;
            }
            break;
            
        case 0x0du:
            if (CheckRemainingSize(packet, 1) == NS_TRUE) {
                option->delta = ((unsigned int) packet->raw[packet->position] + 13);
                packet->position += 1;
            }
            break;
            
        default:
            break;
        }

        /* No payload, process length */
        if (processOptions == 1) {
            option->delta += lastOptionNumber;
            lastOptionNumber = option->delta;
	    Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: final option number = %u",
		   option->delta);
            switch (option->length) {           
            case 0x0fu:
                coap->valid = NS_FALSE;
                processOptions = 0;
                break;
                
            case 0x0eu:
                if (CheckRemainingSize(packet, 2) == NS_TRUE) {
                    option->length =
                        ((unsigned int)packet->raw[packet->position] << 8) +
                        ((unsigned int)packet->raw[packet->position + 1] + 269);
                    packet->position += 2;
                }
                break;
                
            case 0x0du:
                if (CheckRemainingSize(packet, 1) == NS_TRUE) {
                    option->length = ((unsigned int)packet->raw[packet->position] + 13);
                    packet->position += 1;
                }
                break;
                
            default:
                break;
            }
            Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: final option length = %u",
		   option->length);
        }

        if (processOptions == 1) {
            if (option->length > 0) {
                if (CheckRemainingSize(packet, option->length) == NS_TRUE) {
                    option->value = &(packet->raw[packet->position]);
                    packet->position += option->length;
                } else {
                    coap->valid = NS_FALSE;
                    processOptions = 0;
                }
            }
        }
        if (processOptions == 1) {
		
            /* Append option to collection */
            coap->options[coap->optionCount++] = option;
	    Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: added option to collection");
            if (CheckRemainingSize(packet, 1) == NS_FALSE) {
		Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: no further options/payload");
                processOptions = 0;
            }
        }
	Ns_Log(Ns_LogCoapDebug, "ParseCoapMessage: finished parsing option/payload");
    }

    return coap->valid;
}


/*
 * Translate CoAP parameters to HTTP.
 *
 * Returns a boolean value indicating success.
 */
static bool Coap2Http(CoapMsg_t *coap, HttpReq_t *http) {
    bool success = NS_TRUE;
    int opt;
    //size_t uutokenLength = 1 + (size_t)(coap->tokenLength * 4) / 2;
    char uutoken[17];
    size_t uutokenLength;
    Ns_DString rawval, *rawvalPtr = &rawval;
    Ns_DString urlenc, *urlencPtr = &urlenc;
    
    /*
     * Method codes:
     *   CoAP supports the following methods which are a subset of those
     *   supported by HTTP
     */
    const char *methods[] = {
            "",
            "GET",
            "POST",
            "PUT",
            "DELETE"
    };

    /* Ns_GetCharsetEncoding("utf-8") would require initialized hash-tables for quick lookup */
    Tcl_Encoding encoding = Tcl_GetEncoding(NULL, "utf-8");

    Ns_DStringInit(rawvalPtr);
    Ns_DStringInit(urlencPtr);

    /*
     * Token
     *   Since the CoAP token consists of 'raw' bytes we need to encode it.
     *   UUencode is available, so let's use it.
     */
    Ns_DStringInit(&http->token);
    uutokenLength = Ns_HtuuEncode(coap->token, coap->tokenLength, uutoken);
    Ns_DStringNAppend(&http->token, uutoken, (int)uutokenLength);

    if (coap->codeValue < 5) {
        http->method = methods[coap->codeValue];
    }
    
    /* Process CoAP options */
    Ns_DStringInit(&http->host);
    Ns_DStringInit(&http->path);
    Ns_DStringInit(&http->query);

    for (opt = 0; opt < coap->optionCount; opt++) {
        Ns_DStringInit(rawvalPtr);
        Ns_DStringInit(urlencPtr);
	
        /*
         * URI options:
         *
         * [nr]  [name]
         *    3  URI host
         *    7  URI port
         *   11  URI path
         *   15  URI query
         */
        if (coap->options[opt]->delta & 0x3u) {
            Ns_DStringNAppend(rawvalPtr, (char *) (coap->options[opt]->value), coap->options[opt]->length);
            if (coap->options[opt]->delta < 4) {
                /* Hosts are not being transcoded from UTF-8 to %-encoding yet (method missing) */
                Ns_DStringNAppend(&http->host, rawvalPtr->string, rawvalPtr->length);
            } else if (coap->options[opt]->delta < 8) {
                Ns_DStringNAppend(&http->host, ":", 1);
                Ns_DStringNAppend(&http->host, rawvalPtr->string, rawvalPtr->length);
            } else if (coap->options[opt]->delta < 12) {
                Ns_UrlPathEncode(urlencPtr, rawvalPtr->string, encoding);
                Ns_DStringNAppend(&http->path, "/", 1);
                Ns_DStringNAppend(&http->path, urlencPtr->string, urlencPtr->length);
            } else if (coap->options[opt]->delta < 16) {
                if (Tcl_DStringLength(&http->query) == 0) {
                    Ns_DStringNAppend(&http->query, "?", 1);
                } else {
                    Ns_DStringNAppend(&http->query, "&", 1);
                }
                Ns_UrlPathEncode(urlencPtr, rawvalPtr->string, encoding);
                Ns_DStringNAppend(&http->query, urlencPtr->string, urlencPtr->length);
            }
        }
    }

    Ns_Log(Ns_LogCoapDebug, "Coap2Http: finished; processed %d CoAP options", coap->optionCount);
    return success;
}


/*
 * Translate a HTTP reply object to a CoAP object
 *
 * Returns a boolean value indicating success.
 */
static bool Http2Coap(HttpRep_t *http, CoapMsg_t *coap, CoapParams_t *params)
{
    bool success = NS_TRUE;

    /* consider conserved CoAP request parameter */
    if (params->tokenLength > 0) {
        memcpy(coap->token, params->token, params->tokenLength);
        coap->tokenLength = params->tokenLength;
    } else {
        coap->tokenLength = 0;
    }
    /* request is of type CON, reply with ACK */
    if (params->type == 0) {
        coap->type = 2;
    } else {
        coap->type = 1;
    }
    /* 
     * matching mID required for piggybacked ACK replies,
     * not forbidden for other replies
     */
    coap->messageID = params->messageID;

    coap->version       = 1;
    coap->codeValue     = http->status;
    Ns_Log(Ns_LogCoapDebug, "Http2Coap: finished; HTTP status: %u", http->status);

    coap->payload       = http->payload;
    coap->payloadLength = http->payloadLength;

    return success;
}


/*
 * Construct a HTTP request from a HTTP object.
 *
 * Returns a boolean value indicating success.
 */
static bool SerializeHttp(HttpReq_t *http, Packet_t *packet)
{
    Ns_DString request;

    Ns_DStringInit(&request);
    Ns_DStringPrintf(&request, "%s %s%s %s\r\n",
		     http->method, Ns_DStringValue(&http->path),
		     Ns_DStringValue(&http->query), HTTP_VERSION);
    //Ns_DStringPrintf(&request, "Host: %s\n", Ns_DStringValue(&(http->host)));
    Ns_DStringPrintf(&request, "Content-Length: 0\r\n");
    Ns_DStringPrintf(&request, "\r\n");
    memcpy(packet->raw,
	   Ns_DStringValue(&request),
	   (size_t)Ns_DStringLength(&request));
    packet->size = Ns_DStringLength(&request);

    Ns_Log(Ns_LogCoapDebug, "SerializeHttp: finished; HTTP output:\n%s", Ns_DStringValue(&request));

    return NS_TRUE;
}


#if 1
static bool ParseHttp(Packet_t *packet, HttpRep_t *http)
{
    Ns_ReturnCode status;

    Ns_Log(Ns_LogCoapDebug, "ParseHttp started <%s>", packet->raw);

    http->headers = Ns_SetCreate("headers");
    status = Ns_HttpMessageParse((char *)packet->raw, packet->size,
                                 http->headers,
                                 NULL, NULL,
                                 &http->status,
                                 (char **)&http->payload);

    http->payloadLength = (packet->size - (int)(http->payload - packet->raw));

    Ns_Log(Ns_LogCoapDebug, "ParseHttp: finished; headers: %d, payload length: %u, packet size: %u",
           (int)http->headers->size, http->payloadLength, packet->size);

    return NS_TRUE;
}
#else
static bool ParseHttp(Packet_t *packet, HttpRep_t *http)
{
    int         pos, lineStart;
    char        status[4];
    Ns_DString  headerLine;

    Ns_Log(Ns_LogCoapDebug, "ParseHttp started <%s>", packet->raw);

    /* Save status code */
    memcpy(&status[0], &packet->raw[9], 3);
    status[3] = '\0';
    http->status = (int)strtol(&status[0], NULL, 10);

    /*
     * Split reply headers into lines
     */
    http->headers = Ns_SetCreate("headers");
    for (pos = 11, lineStart = 11; pos < packet->size; pos++) {
        if (packet->raw[pos] == '\n') {
            /* Found line break, peek for proper body separator */
            if (packet->raw[pos - 1] == '\r'
                && packet->size >= pos + 2
                && !memcmp(&(packet->raw[pos + 1]), "\r\n", 2)) {
                /* Body seperator found: save payload coordinates, stop parsing */
                pos += 3;
                if (packet->size > pos) {
                    http->payload = &(packet->raw[pos]);
                    http->payloadLength = (packet->size - pos);
                }
                break;
            } else {
                /* Preliminarily increase pos for easier calculations */
                pos++;
                /* New header line, save it */
                Ns_DStringInit(&headerLine);
                Ns_DStringNAppend(&headerLine, (char *)&(packet->raw[lineStart]), (pos - lineStart));
                Ns_ParseHeader(http->headers, Ns_DStringValue(&headerLine), ToLower);
                /* Remember beginning of new line (might be needed later) */
                lineStart = pos;
            }
        }
    }
    
    Ns_DStringFree(&headerLine);
    Ns_Log(Ns_LogCoapDebug, "ParseHttp: finished; headers: %d, payload length: %u, packet size: %u",
           (int)http->headers->size, http->payloadLength, packet->size);

    return NS_TRUE;
}
#endif


/*
 * Construct a CoAP message from a CoAP object.
 */
static bool SerializeCoap (CoapMsg_t *coap, Packet_t *packet) {
    int       delta, o, pdelta = 0, pos;
    Option_t *opt;

    /* Mandatory headers */
    packet->raw[0] = (byte)((coap->version << 6) |
                            (coap->type << 4) |
                            (coap->tokenLength));
    packet->raw[1] = Http2CoapCode(coap->codeValue);
    packet->raw[2] = (byte)((coap->messageID >> 8) & 0xffu);
    packet->raw[3] = (byte)(coap->messageID & 0xffu);
    memcpy(&packet->raw[4], coap->token, (size_t)coap->tokenLength);
    pos = (int)(4 + coap->tokenLength);

    /* Options */
    for (o = 0; o < coap->optionCount; o++) {
        int dlpos;

        opt = coap->options[o];
        /* Option code */
        delta = opt->delta - pdelta;
        pdelta = opt->delta;
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
            pos += 1;
        } else {
            packet->raw[dlpos] = (byte)(delta << 4);
        }
        /* Option length */
        if (opt->length > 268) {
            packet->raw[dlpos] |= 0xeu;
            delta -= 269;
            memcpy(&packet->raw[pos], &opt->length, 2);
            pos += 2;
        } else if (opt->length > 12) {
            packet->raw[dlpos] |= 0xdu;
            delta -= 13;
            memcpy(&packet->raw[pos], &opt->length, 1);
            pos += 1;
        } else {
            packet->raw[dlpos] |= (opt->length & 0xfu);
        }
    }

    /* Payload marker + payload */
    if (coap->payloadLength > 0) {
        int maxlen;

        packet->raw[pos++] = 0xffu;
        maxlen = MAX_COAP_SIZE - pos;
        maxlen = coap->payloadLength > maxlen ? maxlen : coap->payloadLength;
        memcpy(&(packet->raw[pos]), coap->payload, (size_t)maxlen);
        pos += maxlen;
    }

    packet->size = pos;

    return NS_TRUE;
}


/*
 * Allocate memory for a CoAP object and initialize some properties.
 */
static CoapMsg_t *InitCoapMsg(void)
{
    CoapMsg_t *coap = ns_calloc(1u, sizeof(CoapMsg_t));
    coap->valid         = 0;
    coap->tokenLength   = 0;
    coap->optionCount   = 0;
    coap->payloadLength = 0;

    return coap;
}

static byte
Http2CoapCode(int http)
{
    int i;
    byte coap = 0;
    struct code {
        int http;
        byte coap;
    } codes[] = {
        { 200, 0x45u }
    };

    for (i = 0; i < sizeof(codes) / sizeof(struct code); i++) {
        if (http == codes[i].http) {
            coap = codes[i].coap;
            break;
        }
    }

    /* If there's no matching entry convert code to CoAP format */
    if (!coap) {
        coap = (byte)(((http / 100 & 0x7u) << 5) |
                      (http % 100 & 0x1fu));
    }

    return coap;
}
/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
