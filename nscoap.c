/*
 * CoAP to HTTP converter, standalone version
 */

#include "nscoap.h"

int main(int argc, char *argv[])
{
    CoapMsg_t *coap = InitCoapMsg();
    char *file_in, *file_out;
    HttpReq_t *http_req = ns_malloc(sizeof(HttpReq_t));
    HttpRep_t *http_rep = ns_malloc(sizeof(HttpRep_t));
    Packet_t *packet_in = ns_malloc(sizeof(Packet_t));
    Packet_t *packet_out = ns_malloc(sizeof(Packet_t));

    Tcl_FindExecutable(argv[0]);

    bzero(http_rep, sizeof(HttpRep_t));
    bzero(http_req, sizeof(HttpReq_t));
    bzero(packet_in, sizeof(Packet_t));
    bzero(packet_out, sizeof(Packet_t));

    if (argc != 3) {
        fprintf(stderr, "Usage: nscoap { c2h | h2c } file\n");
        exit(-1);
    }
    file_in = argv[2];
    if (LoadPacketFromFile(file_in, packet_in) == NS_FALSE) {
        fprintf(stderr, "File could not be read.\n");
        exit(-1);
    }
    file_out = ns_malloc(strlen(file_in) + 6);
    file_out[0] = '\0';
    strcat(file_out, file_in);
    if (strcmp(argv[1], "c2h") == 0) {
        ParseCoapMessage(packet_in, coap);
        TranslateCoap2Http(coap, http_req);
        ConstructHttpRequest(http_req, packet_out);
        strcat(file_out, ".http");
    } else if (strcmp(argv[1], "h2c") == 0) {
        ParseHttpReply(packet_in, http_rep);
        TranslateHttp2Coap(http_rep, coap);
        ConstructCoapMessage(coap, packet_out);
        /* for debugging only */
        ParseCoapMessage(packet_out, coap);
        strcat(file_out, ".coap");
    } else {
        fprintf(stderr, "Usage: nscoap { c2h | h2c } file\n");
        exit(-1);
    }
    WritePacketToFile(packet_out, file_out);

    FreeCoapMsg(coap);
    ns_free(http_req);
    ns_free(file_out);

    return 0;
}

/*
 * Loads a packet from a given file descriptor.
 *
 * Returns the size of the message in bytes if successful, otherwise 0.
 */
static int LoadPacketFromFile(char *file, Packet_t *packet)
{
    bool success = NS_TRUE;
    FILE *fd = fopen(file, "r");

#ifdef DEBUG
    fprintf(stderr, "----- LoadPacketFromFile started. -----\n");
#endif

    if (fd) {
        packet->size = (int)fread(packet->raw, 1, MAX_PACKET_SIZE, fd);
        fclose(fd);
#ifdef DEBUG
        fprintf(stderr, "Packet size: %d.\n", packet->size);
#endif
    } else {
        fprintf(stderr, "File <%s> could not be opened.\n", file);
        success = NS_FALSE;
    }
    return success;
}

/*
 * Writes a packet to a file descriptor.
 *
 * Returns a boolean value indicating success.
 */
static bool WritePacketToFile(Packet_t *packet, char *file)
{
    bool success = NS_FALSE;
    FILE *fd = fopen(file, "w");

    if (fd && fwrite(packet, 1, (size_t)packet->size, fd) > 0) {
        success = NS_TRUE;
    }

    return success;
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
static bool ParseCoapMessage(Packet_t *packet, CoapMsg_t *coap) {
    Option_t   *option;
    int         i, codeValue, lastOptionNumber = 0;
    bool        processOptions;
    Code_t      code;
    /*
     * Registry of valid CoAP message codes
     */
    static const int code_registry[] = {
        000, 001, 002, 003, 004,
        201, 202, 203, 204, 205,
        400, 401, 402, 403, 404, 405, 406, 412, 413, 415,
        500, 501, 502, 503, 504, 505
    };

    packet->position = 0;
    coap->valid = NS_TRUE;

#ifdef DEBUG
    fprintf(stderr, "----- ParseCoapMessage started. -----\n");
#endif
    /*
     * CoAP messages can't be shorter than 4 bytes
     */
    if (CheckRemainingSize(packet, 4) == NS_FALSE) {
#ifdef DEBUG
        fprintf(stderr, "Message shorter than 4 bytes.\n");
#endif
        return NS_FALSE;
    }

    /*
     * Bit 0-1: CoAP version: Must be 0b01
     */
    coap->version = ((packet->raw[0] >> 6) == 0x1u);
#ifdef DEBUG
    fprintf(stderr, "CoAP version: %d\n", coap->version);
#endif
    if (coap->version == 0) {
        coap->valid = NS_FALSE;
        return NS_FALSE;
    }

    /*
     * Bit 2-3: Type of CoAP message
     */
    coap->type = ((packet->raw[0] >> 4) & 0x30u);
#ifdef DEBUG
    fprintf(stderr, "Message type: %d\n", coap->type);
#endif

    /*
     * Bit 4-7: Token Length
     */
    coap->tokenLength = (packet->raw[0] & 0x0fu);
#ifdef DEBUG
    fprintf(stderr, "Token length: %d\n", (int)coap->tokenLength);
#endif

    if (coap->tokenLength > 8) {
        coap->valid = NS_FALSE;
        return NS_FALSE;
    }

    /*
     * Bit 8-15: Message Code
     */
    code.class  = ((packet->raw[1] >> 5) & 0x7u);
    code.detail = (packet->raw[1] & 0x1fu);
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
            coap->codeValue = codeValue;
            break;
        }
    }
    if (coap->codeValue == 0) {
        return NS_FALSE;
    }

    /*
     * Bit 16-31: Message ID
     */
    coap->messageID = ((unsigned int) packet->raw[2] << 8) + (unsigned int) packet->raw[3];
#ifdef DEBUG
    fprintf(stderr, "messageID: %d\n", coap->messageID);
#endif

    /*
     * Bit 32ff: Token
     */
    packet->position = 4;
    if (coap->tokenLength > 0) {
        if (CheckRemainingSize(packet, (int)coap->tokenLength) == NS_TRUE) {
            coap->token = &(packet->raw[4]);
            packet->position += coap->tokenLength;
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
                coap->payload = &(packet->raw[packet->position]);
                coap->payloadLength = packet->size - packet->position;
#ifdef DEBUG
                fprintf(stderr, "Payload marker detected. Payload length = %d.\n",
                        coap->payloadLength);
#endif
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
                    ((unsigned int) packet->raw[packet->position + 1] - 269);
                packet->position += 2;
            }
            break;
            
        case 0x0du:
            if (CheckRemainingSize(packet, 1) == NS_TRUE) {
                option->delta = ((unsigned int) packet->raw[packet->position] - 13);
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
#ifdef DEBUG
            fprintf(stderr, "Final option number = %u, length = %u.\n",
                    option->delta, option->length);
#endif
            switch (option->length) {
                
            case 0x0fu:
                coap->valid = NS_FALSE;
                processOptions = 0;
                break;
                
            case 0x0eu:
                if (CheckRemainingSize(packet, 2) == NS_TRUE) {
                    option->length =
                        ((unsigned int) packet->raw[packet->position] << 8) +
                        ((unsigned int) packet->raw[packet->position + 1] - 269);
                    packet->position += 2;
                }
                break;
                
            case 0x0du:
                if (CheckRemainingSize(packet, 1) == NS_TRUE) {
                    option->length = ((unsigned int) packet->raw[packet->position] - 13);
                    packet->position += 1;
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
                if (CheckRemainingSize(packet, option->length) == NS_TRUE) {
#ifdef DEBUG
                    fprintf(stderr, "found.\n");
#endif
                    option->value = &(packet->raw[packet->position]);
                    packet->position += option->length;
                } else {
#ifdef DEBUG
                    fprintf(stderr, "NOT found.\n");
#endif
                    coap->valid = NS_FALSE;
                    processOptions = 0;
                }
            }
        }
        if (processOptions == 1) {
            /*
             * Append option to collection
             */
            coap->options[coap->optionCount++] = option;
#ifdef DEBUG
            fprintf(stderr, "Added option to collection.\n");
#endif

            if (CheckRemainingSize(packet, 1) == NS_FALSE) {
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
    return coap->valid;
}

/*
 * Translate CoAP parameters to HTTP.
 *
 * Returns a boolean value indicating success.
 */
static bool TranslateCoap2Http(CoapMsg_t *coap, HttpReq_t *http) {
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

    /*
     * Process CoAP options
     */
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

    return success;
}

/*
 * Translate a HTTP reply object to a CoAP object
 *
 * Returns a boolean value indicating success.
 */
static bool TranslateHttp2Coap(HttpRep_t *http, CoapMsg_t *coap)
{
    bool success = NS_TRUE;
    byte token[8];
    char *uuToken;

#ifdef DEBUG
    fprintf(stderr, "----- TranslateHttp2Coap started. -----\n");
#endif

    uuToken = Ns_SetIGet(http->headers, "x-coap-token");
    if (uuToken == NULL) {
        coap->tokenLength = 0;
    } else {
        coap->tokenLength = Ns_HtuuDecode(uuToken, &token[0], strlen(uuToken));
        memcpy(coap->token, &token[0], coap->tokenLength);
    }

    coap->version       = 1;
    coap->codeValue     = http->status;
#ifdef DEBUG
    fprintf(stderr, "HTTP status: %u\n", http->status);
#endif
    /* Fake message ID until we match the one of the request. */
    coap->messageID     = 0xbeefu;
    coap->payload       = http->payload;
    coap->payloadLength = http->payloadLength;

    return success;
}

/*
 * Construct a HTTP request from a HTTP object.
 *
 * Returns a boolean value indicating success.
 */
static bool ConstructHttpRequest(HttpReq_t *http, Packet_t *packet)
{
    Ns_DString request;

    Ns_DStringInit(&request);
    Ns_DStringPrintf(&request, "%s %s%s %s\n", http->method, Ns_DStringValue(&http->path), Ns_DStringValue(&http->query), HTTP_VERSION);
    Ns_DStringPrintf(&request, "Host: %s\n", Ns_DStringValue(&http->host));
    memcpy(&packet->raw[0], Ns_DStringValue(&request), (size_t)Ns_DStringLength(&request));
    packet->size = Ns_DStringLength(&request);

    #ifdef DEBUG
        fprintf(stderr, "\n");
        fprintf(stderr, "=== HTTP output: ===\n");
        fprintf(stderr, "%s\n", Ns_DStringValue(&request));
    #endif

    Ns_DStringFree(&request);

    return NS_TRUE;
}

static bool ParseHttpReply(Packet_t *packet, HttpRep_t *http)
{
    int         pos, lastPos;
    char        status[4];
    Ns_DString  headerLine;

#ifdef DEBUG
    fprintf(stderr, "----- ParseHttpReply started. -----\n");
#endif

    /* Save status code */
        memcpy(&status[0], &packet->raw[9], 3);
    status[4] = '\0';
    http->status = (int) strtol(&status[0], NULL, 10);

    /*
     * Split reply headers into lines
     */
    http->headers = Ns_SetCreate("headers");
    for (pos = 11, lastPos = 11; pos < packet->size; pos++) {
        if (packet->raw[pos] == '\n') {
            if (pos == (lastPos + 1)) {
                /*
                 * Found body seperator:
                 * Omit line, save payload coordinates, stop parsing
                 */
                if (packet->size > ++pos) {
                    http->payload = &packet->raw[pos];
                    http->payloadLength = (packet->size - pos);
                }
                break;
            } else {
                /* Move to first char of new line */
                lastPos++;
                Ns_DStringInit(&headerLine);
                Ns_DStringNAppend(&headerLine, (char *)&packet->raw[lastPos], (pos - lastPos));
                Ns_ParseHeader(http->headers, Ns_DStringValue(&headerLine), ToLower);
                lastPos = pos;
                Ns_DStringFree(&headerLine);
            }
        }
    }
#ifdef DEBUG
    Ns_SetPrint(http->headers);
    fprintf(stderr, "Packet size: %u\n", packet->size);
    fprintf(stderr, "Payload length: %u\n", http->payloadLength);
#endif


    return NS_TRUE;
}

/*
 * Construct a CoAP message from a CoAP object.
 */
static bool ConstructCoapMessage (CoapMsg_t *coap, Packet_t *packet) {
    int delta, dlpos, o, pdelta = 0, pos;
    Option_t *opt;

#ifdef DEBUG
    fprintf(stderr, "----- ConstructCoapMessage started. -----\n");
#endif

    /* Mandatory headers. */
    packet->raw[0] = (byte) ((coap->version << 6) |
            (coap->type << 4) |
            (coap->tokenLength));
    packet->raw[1] = (byte) (((coap->codeValue / 100 & 0x7u) << 5) |
            (coap->codeValue & 0x1fu));
    packet->raw[2] = (byte) (((coap->messageID >> 8) & 0xffu));
    packet->raw[3] = (byte) (coap->messageID & 0xffu);
    memcpy(&packet->raw[4], coap->token, (size_t)coap->tokenLength);
    pos = (int)(4 + coap->tokenLength);

    /* Options. */
    for (o = 0; o < coap->optionCount; o++) {
        opt = coap->options[o];
        /* Option code. */
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
        /* Option length. */
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

    /* Payload marker + payload. */
    if (coap->payloadLength > 0) {
        packet->raw[pos++] = 0xffu;
        memcpy(&packet->raw[pos], coap->payload, (size_t)coap->payloadLength);
        pos += coap->payloadLength;
    }

    packet->size = pos;

    return NS_TRUE;
}

/*
 * Allocate memory for a CoAP object and initialize some properties.
 */
static CoapMsg_t *InitCoapMsg(void)
{
    CoapMsg_t *coap = ns_malloc(sizeof(CoapMsg_t));
    bzero(coap, sizeof(CoapMsg_t));
    coap->valid         = 0;
    coap->tokenLength   = 0;
    coap->optionCount   = 0;
    coap->payloadLength = 0;

    return coap;
}

/*
 * Free a CoAP object and its properties.
 */
static void FreeCoapMsg(CoapMsg_t *coap)
{
    size_t o;

    for (o = 1; o <= coap->optionCount; o++) {
        ns_free(coap->options[coap->optionCount]);
    }
    ns_free(coap);

    return;
}

/*
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
