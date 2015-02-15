/*
 * CoAP to HTTP converter, standalone version
 */

#include <ns.h>

/*
 * Control debug output
 */
#define DEBUG 1

/*
 * Maximum size (bytes) of a CoAP message as suggested by RFC 7252
 */
#define MAX_SIZE 1152

/*
 * Beginning of declarations (will be moved to .h later)
 */

typedef unsigned char byte;

/*
 * Message code details
 */
typedef struct Code_s
{
    int     class;
    int     detail;
} Code_t;

typedef struct Option_s
{
    unsigned int delta;
    unsigned int length;
    byte        *value;
} Option_t;

/*
 * Holds the request and its parameters
 */
typedef struct Request_s
{
    byte        raw[MAX_SIZE];  /* holds the raw packet */
    int         size;           /* size in bytes */
    bool        valid;          /* validity of the request */
    int         position;       /* current parser position */
    int         version;        /* CoAP version */
    int         type;           /* message type */
    int         tokenLength;    /* token length */
    int         codeValue;      /* message code */
    int         messageID;      /* message id */
    byte        *token;         /* token */
    byte        *payload;       /* payload */
    int         payloadLength;  /* length of payload */
    int         optionCount;    /* number of valid options */
    Option_t    options[MAX_SIZE - 4];
} Request_t;

static bool LoadMessage(char *file, Request_t *request);
static bool ParseRequest(Request_t *request);

/*
 * End of declarations
 */

int main(int argc, char *argv[])
{
    Request_t request;

    bzero(&request, sizeof(Request_t));
    request.valid = NS_TRUE;

    if (argc != 2) {
        fprintf(stderr, "Usage: coap2http <captured.file>\n");
        exit(-1);
    }
    if (LoadMessage(argv[1], &request) == NS_TRUE) {
        printf("Result: %d\n", ParseRequest(&request));
    }

    return 0;
}

/*
 * Load message from file and save it to buffer together with its size
 */
static bool LoadMessage(char *file, Request_t *request)
{
    FILE *fd;
    bool success = NS_TRUE;

    if ((fd = fopen(file, "r"))) {
        request->size = (int) fread(request->raw, 1, MAX_SIZE, fd);
        fclose(fd);
    } else {
        fprintf(stderr, "File <%s> could not be opened.\n", file);
        success = NS_FALSE;
    }

    return success;
}

/*
 * Check size of the CoAP message
 */
static bool CheckRemainingSize(Request_t *request, int increment)
{
    bool success = NS_TRUE;

    if ((request->position + increment) > request->size) {
        request->valid = NS_FALSE;
        success = NS_FALSE;
    }

    return success;
}

/*
 * Parse the content of a CoAP request
 */
static bool ParseRequest(Request_t *request) {
    Option_t option;
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
    bzero(&option, sizeof(Option_t));
    request->valid = NS_TRUE;

#ifdef DEBUG
    printf("parseRequest started.\n");
#endif
    /*
     * CoAP messages can't be shorter than 4 bytes
     */
    if (CheckRemainingSize(request, 4) == NS_FALSE) {
#ifdef DEBUG
        printf("Message shorter than 4 bytes.\n");
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
     * Bit 8-15: Token Length
     */
    code.class  = ((request->raw[1] >> 5) & 0x7u);
    code.detail = (request->raw[1] & 0x1fu);
    codeValue   = code.class * 100 + code.detail;
#ifdef DEBUG
    printf("Message code: %d\n", codeValue);
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
        option.delta = ((request->raw[request->position] >> 4) & 0x0fu);
        option.length = (request->raw[request->position] & 0x0fu);
        request->position++;
#ifdef DEBUG
        printf("Processing option: number delta = %u, length = %u.\n",
               option.delta, option.length);
#endif
        /*
         * Parse option delta
         */
        switch (option.delta) {
            
        case 0x0fu:
            /*
             * Payload marker or invalid
             */
            switch (option.length) {
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
                option.delta =
                    ((unsigned int)request->raw[request->position] >> 8) +
                    ((unsigned int)request->raw[request->position + 1] - 269);
                request->position += 2;
            }
            break;
            
        case 0x0du:
            if (CheckRemainingSize(request, 1) == NS_TRUE) {
                option.delta = (int) request->raw[request->position] - 13;
                request->position += 1;
            }
            break;
            
        default:
            break;
        }

        /*
         * No payload, process length
         */
        if (processOptions) {
            switch (option.length) {
                
            case 0x0fu:
                request->valid = NS_FALSE;
                processOptions = 0;
                break;
                
            case 0x0eu:
                if (CheckRemainingSize(request, 2) == NS_TRUE) {
                    option.length =
                        ((unsigned int) request->raw[request->position] >> 8) +
                        ((unsigned int) request->raw[request->position + 1] - 269);
                    request->position += 2;
                }
                break;
                
            case 0x0du:
                if (CheckRemainingSize(request, 1) == NS_TRUE) {
                    option.length = (int) request->raw[request->position] - 13;
                    request->position += 1;
                }
                break;
                
            default:
                break;
            }
        }
        
        option.delta += lastOptionNumber;
        lastOptionNumber = option.delta;
#ifdef DEBUG
        fprintf(stderr, "Final option number = %u, length = %u.\n",
                option.delta, option.length);
#endif

        if (processOptions) {
            if (option.length > 0) {
#ifdef DEBUG
                fprintf(stderr, "Option value expected … ");
#endif
                if (CheckRemainingSize(request, option.length) == NS_TRUE) {
#ifdef DEBUG
                    fprintf(stderr, "found.\n");
#endif
                    option.value = &(request->raw[request->position]);
                    request->position += option.length;
                } else {
#ifdef DEBUG
                    fprintf(stderr, "NOT found.\n");
#endif
                    request->valid = NS_FALSE;
                    processOptions = 0;
                }
            }
        }
        if (processOptions) {
            /*
             * Append option to collection
             */
            request->options[request->optionCount] = option;
            request->optionCount++;
#ifdef DEBUG
            printf("Added option to collection.\n");
#endif

            if (CheckRemainingSize(request, 1) == NS_FALSE) {
#ifdef DEBUG
                printf("No further options/payload.\n");
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
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
