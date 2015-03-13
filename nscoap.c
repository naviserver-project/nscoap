/*
 * CoAP to HTTP converter, standalone version
 */

#include "nscoap.h"

int main(int argc, char *argv[])
{
    CoapMsg_t *coap = ns_malloc(sizeof(CoapMsg_t));
    HttpReq_t *http_req = ns_malloc(sizeof(HttpReq_t));
    HttpRep_t *http_rep = ns_malloc(sizeof(HttpRep_t));

    Tcl_FindExecutable(argv[0]);

    bzero(coap, sizeof(CoapMsg_t));
    coap->valid = NS_TRUE;
    bzero(http_rep, sizeof(HttpRep_t));
    http_rep->valid = NS_TRUE;
    bzero(http_req, sizeof(HttpReq_t));
    http_req->coap = coap;

    if (argc == 2 && strcmp(argv[1], "coap") == 0) {
        if (LoadCoapMessage(coap, http_rep, argv[1]) == NS_TRUE) {
            fprintf(stderr, "Result: %d\n", ParseCoapMessage(coap));
            ConstructHttpRequest(http_req);
        }
    } else if (argc == 2 && strcmp(argv[1], "http") == 0) {
        if (LoadCoapMessage(coap, http_rep, argv[1]) == NS_TRUE) {
            ParseHttpReply(http_rep);
        }
    } else {
        fprintf(stderr, "Usage: nscoap { coap | http } \n");
        fprintf(stderr, "Write request to stdin, e.g. cat coap_capture.file | ./nscoap coap\n");
        exit(-1);
    }

    ns_free(coap);
    ns_free(http_req);

    return 0;
}

/*
 * Load message from file and save it to buffer together with its size
 */
static int LoadCoapMessage(CoapMsg_t *coap, HttpRep_t *http, char *protocol)
{
    bool    success = NS_TRUE;

    if (strcmp(protocol, "coap") == 0) {
        coap->size = (int) fread(coap->raw, 1, MAX_COAP_SIZE, stdin);
    } else if (strcmp(protocol, "http") == 0) {
        http->size = (int) fread(http->raw, 1, MAX_HTTP_SIZE, stdin);
    } else {
        fprintf(stderr, "Unsupported protocol.\n");
        success = NS_FALSE;
    }

    return success;
}

/*
 * Check size of the CoAP message
 */
static bool CheckRemainingSize(CoapMsg_t *coap, int increment)
{
    bool success = NS_TRUE;

    if ((coap->position + increment) > coap->size) {
        coap->valid = NS_FALSE;
        success = NS_FALSE;
    }

    return success;
}

/*
 * Parse the content of a CoAP request
 */
static bool ParseCoapMessage(CoapMsg_t *request) {
    Option_t *option;
    int      i, codeValue, lastOptionNumber = 0;
    bool     processOptions;
    Code_t   code;
    /*
     * Registry of valid CoAP message codes
     */
    static const int code_registry[] = {
        000, 001, 002, 003, 004,
        201, 202, 203, 204, 205,
        400, 401, 402, 403, 404, 405, 406, 412, 413, 415,
        500, 501, 502, 503, 504, 505
    };

    request->position = 0;
    request->valid = NS_TRUE;

#ifdef DEBUG
    fprintf(stderr, "parseRequest started.\n");
#endif
    /*
     * CoAP messages can't be shorter than 4 bytes
     */
    if (CheckRemainingSize(request, 4) == NS_FALSE) {
#ifdef DEBUG
        fprintf(stderr, "Message shorter than 4 bytes.\n");
#endif
        return NS_FALSE;
    }

    /*
     * Bit 0-1: CoAP version: Must be 0b01
     */
    request->version = ((request->raw[0] >> 6) == 0x1u);
#ifdef DEBUG
    fprintf(stderr, "CoAP version: %d\n", request->version);
#endif
    if (request->version == 0) {
        request->valid = NS_FALSE;
        return NS_FALSE;
    }

    /*
     * Bit 2-3: Type of CoAP message
     */
    request->type = ((request->raw[0] >> 4) & 0x30u);
#ifdef DEBUG
    fprintf(stderr, "Message type: %d\n", request->type);
#endif

    /*
     * Bit 4-7: Token Length
     */
    request->tokenLength = (request->raw[0] & 0x0fu);
#ifdef DEBUG
    fprintf(stderr, "Token length: %d\n", request->tokenLength);
#endif

    if (request->tokenLength > 8) {
        request->valid = NS_FALSE;
        return NS_FALSE;
    }

    /*
     * Bit 8-15: Message Code
     */
    code.class  = ((request->raw[1] >> 5) & 0x7u);
    code.detail = (request->raw[1] & 0x1fu);
    codeValue   = code.class * 100 + code.detail;
#ifdef DEBUG
    fprintf(stderr, "Message code: %d\n", codeValue);
#endif

    /*
     * Check, if the code belongs to the codes defined by the CoAP RFC.  If
     * not, we report the request being not valid (which might be a little
     * harsh for some applications).
     */
    for (i = 0; i < (sizeof(code_registry) / sizeof(int)); i++) {
        if (code_registry[i] == codeValue) {
            request->codeValue = codeValue;
            break;
        }
    }
    if (request->codeValue == 0) {
        return NS_FALSE;
    }

    /*
     * Bit 16-31: Message ID
     */
    request->messageID = ((unsigned int)request->raw[2] << 8) + (unsigned int)request->raw[3];
#ifdef DEBUG
    fprintf(stderr, "messageID: %d\n", request->messageID);
#endif

    /*
     * Bit 32ff: Token
     */
    request->position = 4;
    if (request->tokenLength > 0) {
        if (CheckRemainingSize(request, request->tokenLength) == NS_TRUE) {
            request->token = &(request->raw[4]);
            request->position += request->tokenLength;
#ifdef DEBUG
            fprintf(stderr, "Valid token found.\n");
#endif
        } else {
            return NS_FALSE;
        }
    }

    /*
     * Options. Option Numbers are maintained in the "CoAP Option Numbers"
     * registry.
     */
    processOptions = CheckRemainingSize(request, 1);

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
        option = malloc(sizeof(Option_t));
        bzero(option, sizeof(Option_t));
        option->delta = ((request->raw[request->position] >> 4) & 0x0fu);
        option->length = (request->raw[request->position] & 0x0fu);
        request->position++;
#ifdef DEBUG
        fprintf(stderr, "Processing option: number delta = %u, length = %u.\n",
               option->delta, option->length);
#endif
        /*
         * Parse option delta
         */
        switch (option->delta) {
            
        case 0x0fu:
            /*
             * Payload marker or invalid
             */
            switch (option->length) {
            case 0x0fu:
                request->payload = &(request->raw[request->position]);
                request->payloadLength = request->size - request->position;
#ifdef DEBUG
                fprintf(stderr, "Payload marker detected. Payload length = %d.\n",
                        request->payloadLength);
#endif
                break;
            default:
                request->valid = NS_FALSE;
                break;
            }
            processOptions = 0;
            break;

        case 0x0eu:
            if (CheckRemainingSize(request, 2) == NS_TRUE) {
                option->delta =
                    ((unsigned int)request->raw[request->position] << 8) +
                    ((unsigned int)request->raw[request->position + 1] - 269);
                request->position += 2;
            }
            break;
            
        case 0x0du:
            if (CheckRemainingSize(request, 1) == NS_TRUE) {
                option->delta = ((unsigned int)request->raw[request->position] - 13);
                request->position += 1;
            }
            break;
            
        default:
            break;
        }

        /* No payload, process length */
        if (processOptions == 1) {
            option->delta += lastOptionNumber;
            lastOptionNumber = option->delta;
#ifdef DEBUG
            fprintf(stderr, "Final option number = %u, length = %u.\n",
                    option->delta, option->length);
#endif
            switch (option->length) {
                
            case 0x0fu:
                request->valid = NS_FALSE;
                processOptions = 0;
                break;
                
            case 0x0eu:
                if (CheckRemainingSize(request, 2) == NS_TRUE) {
                    option->length =
                        ((unsigned int)request->raw[request->position] << 8) +
                        ((unsigned int)request->raw[request->position + 1] - 269);
                    request->position += 2;
                }
                break;
                
            case 0x0du:
                if (CheckRemainingSize(request, 1) == NS_TRUE) {
                    option->length = ((unsigned int)request->raw[request->position] - 13);
                    request->position += 1;
                }
                break;
                
            default:
                break;
            }
        }

        if (processOptions == 1) {
            if (option->length > 0) {
#ifdef DEBUG
                fprintf(stderr, "Option value expected … ");
#endif
                if (CheckRemainingSize(request, option->length) == NS_TRUE) {
#ifdef DEBUG
                    fprintf(stderr, "found.\n");
#endif
                    option->value = &(request->raw[request->position]);
                    request->position += option->length;
                } else {
#ifdef DEBUG
                    fprintf(stderr, "NOT found.\n");
#endif
                    request->valid = NS_FALSE;
                    processOptions = 0;
                }
            }
        }
        if (processOptions == 1) {
            /*
             * Append option to collection
             */
            request->options[request->optionCount] = option;
            request->optionCount++;
#ifdef DEBUG
            fprintf(stderr, "Added option to collection.\n");
#endif

            if (CheckRemainingSize(request, 1) == NS_FALSE) {
#ifdef DEBUG
                fprintf(stderr, "No further options/payload.\n");
#endif
                processOptions = 0;
            }
        }
#ifdef DEBUG
        fprintf(stderr, "Finished parsing option/payload.\n");
#endif

    }
#ifdef DEBUG
    fprintf(stderr, "parseRequest finished.\n");
#endif
    return request->valid;
}

/*
 * Translate CoAP parameters to HTTP
 */
static bool ConstructHttpRequest (HttpReq_t *http)
{
    int opt;
    CoapMsg_t *coap = http->coap;
    Ns_DString optval, *optvalPtr = &optval;
    Ns_DString urlenc, *urlencPtr = &urlenc;
    Tcl_Encoding encoding = Tcl_GetEncoding(NULL, "utf-8");
    /* Ns_GetCharsetEncoding("utf-8") would requires initialized hash-tables for quick lookup */

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

    Ns_DStringInit(&http->host);
    Ns_DStringInit(&http->path);
    Ns_DStringInit(&http->query);
    if (coap->codeValue < 5) {
        http->method = methods[coap->codeValue];
    }

    /*
     * Process CoAP options
     */
    for (opt = 0; opt < coap->optionCount; opt++) {
        Ns_DStringInit(optvalPtr);
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
            Ns_DStringNAppend(optvalPtr, (char *)(coap->options[opt]->value), coap->options[opt]->length);
            if (coap->options[opt]->delta < 4) {
                /* Hosts are not being transcoded from UTF-8 to %-encoding yet (method missing) */
                Ns_DStringNAppend(&http->host, optvalPtr->string, optvalPtr->length);
            } else if (coap->options[opt]->delta < 8) {
                Ns_DStringNAppend(&http->host, ":", 1);
                Ns_DStringNAppend(&http->host, optvalPtr->string, optvalPtr->length);
            } else if (coap->options[opt]->delta < 12) {
                Ns_UrlPathEncode(urlencPtr, optvalPtr->string, encoding);
                Ns_DStringNAppend(&http->path, "/", 1);
                Ns_DStringNAppend(&http->path, urlencPtr->string, urlencPtr->length);
            } else if (coap->options[opt]->delta < 16) {
                if (Tcl_DStringLength(&http->query) == 0) {
                    Ns_DStringNAppend(&http->query, "?", 1);
                } else {
                    Ns_DStringNAppend(&http->query, "&", 1);
                }
                Ns_UrlPathEncode(urlencPtr, optvalPtr->string, encoding);
                Ns_DStringNAppend(&http->query, urlencPtr->string, urlencPtr->length);
            }
        }
    }
#ifdef DEBUG
    fprintf(stderr, "\n");
    fprintf(stderr, "=== HTTP output: ===\n");
    fprintf(stderr, "%s %s%s %s\n", http->method, Tcl_DStringValue(&http->path), Tcl_DStringValue(&http->query), HTTP_VERSION);
    fprintf(stderr, "Host: %s\n", Tcl_DStringValue(&http->host));
    fprintf(stderr, "\n\n");
#endif
    return NS_TRUE;
}

static bool ParseHttpReply(HttpRep_t *http) {
    int         pos, lastPos;
    Ns_DString  headerLine;

#ifdef DEBUG
    fprintf(stderr, "----- ParseHttpReply started. -----\n");
#endif

    /*
     * Split reply headers into lines
     */
    http->headers = Ns_SetCreate("headers");
    for (pos = 0, lastPos = 0; pos < http->size; pos++) {
        if (http->raw[pos] == '\n') {
            if (pos == (lastPos + 1)) {
                /*
                 * Found body seperator:
                 * Omit line, save payload coordinates, stop parsing
                 */
                if (http->size > ++pos) {
                    http->payload = &http->raw[pos];
                    http->payloadLength = (http->size - pos);
                }
                break;
            } else {
                /* Move to first char of new line */
                lastPos++;
                Ns_DStringInit(&headerLine);
                Ns_DStringNAppend(&headerLine, (char *)&http->raw[lastPos], (pos - lastPos));
                Ns_ParseHeader(http->headers, Ns_DStringValue(&headerLine), ToLower);
                lastPos = pos;
            }
        }
    }
    Ns_DStringFree(&headerLine);
#ifdef DEBUG
    Ns_SetPrint(http->headers);
#endif

    return NS_TRUE;
}

/*
 * Construct a CoAP message from a CoAP object.
 */
static bool ConstructCoapMessage (CoapMsg_t *coap) {
    int delta, dlpos, o, pdelta = 0, pos;
    Option_t *opt;

    /* Mandatory headers. */
    coap->raw[0] = (byte) ((coap->version << 6) &
            (coap->type << 4) &
            (coap->tokenLength));
    coap->raw[1] = (byte) (((coap->codeValue / 100 & 0x7u) << 5) &
            (coap->codeValue & 0x1fu));
    coap->raw[2] = (byte) (((coap->messageID >> 8) & 0xffu));
    coap->raw[3] = (byte) (coap->messageID & 0xffu);
    memcpy(&coap->raw[4], coap->token, (size_t) coap->tokenLength);
    pos = 4 + coap->tokenLength;

    /* Options. */
    for (o = 0; o < coap->optionCount; o++) {
        opt = coap->options[o];
        /* Option code. */
        delta = opt->delta - pdelta;
        pdelta = delta;
        dlpos = pos++;
        if (delta > 268) {
            coap->raw[dlpos] = (0xeu << 4);
            delta -= 269;
            memcpy(&coap->raw[pos], &delta, 2);
            pos += 2;
        } else if (delta > 12) {
            coap->raw[dlpos] = (0xdu << 4);
            delta -= 13;
            memcpy(&coap->raw[pos], &delta, 1);
            pos += 1;
        } else {
            coap->raw[dlpos] = (byte)(delta << 4);
        }
        /* Option length. */
        if (opt->length > 268) {
            coap->raw[dlpos] &= 0xeu;
            delta -= 269;
            memcpy(&coap->raw[pos], &opt->length, 2);
            pos += 2;
        } else if (opt->length > 12) {
            coap->raw[dlpos] &= 0xdu;
            delta -= 13;
            memcpy(&coap->raw[pos], &opt->length, 1);
            pos += 1;
        } else {
            coap->raw[dlpos] &= (opt->length & 0xfu);
        }
    }

    /* Payload marker + payload. */
    if (coap->payloadLength > 0) {
        coap->raw[pos++] = 0xffu;
        memcpy(&coap->raw[pos], coap->payload, (size_t)coap->payloadLength);
    }

    return NS_TRUE;
}

/*
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
