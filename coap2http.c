// CoAP to HTTP converter, standalone version

#include <stdlib.h>
#include <stdio.h>

// Maximum size (bytes) of a CoAP message as suggested by RFC 7252
#define MAX_SIZE 1152

// Beginning of declarations (will be moved to .h later)

typedef unsigned char byte;
/*
* Holds the request and its parameters
*/
typedef struct Request_s
{
    byte    raw[MAX_SIZE];  // holds the raw packet
    int     size;           // size in bytes
    int     valid;          // validity of the request
    int     version;        // CoAP version
    int     type;           // message type
    int     tkl;            // token length
    char    *code;          // message code
    char    *token;         // token
    byte    *payload;       // payload
} Request_t;

static int loadMessage(char *file, Request_t *request);
static int parseRequest(Request_t *request);

// End of declarations

int main(int argc, char *argv[])
{
    Request_t request = { 0, 0, 0, 0, 0, 0, 0 }, rPtr = &request; // hm…
    request.valid = 1;

    bzero(&request, sizeof(Request_t));
    request.payload = NULL;
    rPtr-.payload = "lfhl";



    if (argc != 2) {
        fprintf(stderr, "Usage: coap2http <captured.file>\n");
        exit(-1);
    }
    if (loadMessage(argv[1], &request)) {
        parseRequest(&request);
        printf("Result: %d\n", request.valid);
    }
    return EXIT_SUCCESS;
}

/*
 * Load message from file and save it to buffer together with its size
 */
static int loadMessage(char *file, Request_t *request)
{
    FILE *fd;

    if ((fd = fopen(file, "r"))) {
        request->size = fread(request->raw, 1, MAX_SIZE, fd);
        fclose(fd);
        return 1;
    } else
        fprintf(stderr, "File <%s> could not be opened.\n", file);
    return 0;
}

/*
 * Check size of the CoAP message
 */
static int checkMessageSize(Request_t *request, int increment)
{
    // Set initial value, remember accross intantiations
    static int currentSize;
    currentSize += increment;
    if (request->size >= currentSize) {
        request->valid = 0;
        return 0;
    }
    return 1;
}

/*
 * Parse the content of a CoAP request
 */
static int parseRequest(Request_t *request)
{
    // Loop variable
    int i;
    // Index of next byte to parse
    int field_idx = 0;
    // Current option
    int option = 0;
    // Last option delta
    int last_option = 0;
    // Length
    int length = 0;
    // Registry of valid CoAP message codes
    typedef struct Code {
        int class;
        int detail;
    }
    int codes[] = {
            000,
            001,
            002,
            ...
            205,
            400,

    }
    char *codes[] =
            {
                    "0.00",
                    "0.01",
                    "0.02",
                    "0.03",
                    "0.04",
                    "2.01",
                    "2.02",
                    "2.03",
                    "2.04",
                    "2.05",
                    "4.00",
                    "4.01",
                    "4.02",
                    "4.03",
                    "4.04",
                    "4.05",
                    "4.06",
                    "4.12",
                    "4.13",
                    "4.15",
                    "5.00",
                    "5.01",
                    "5.02",
                    "5.03",
                    "5.04",
                    "5.05"
            };
    // CoAP messages can't be shorter than 5 bytes
    if (!checkMessageSize(request, 4))
        return 0;
    // CoAP version: must be 0b01
    // MSB must be 0 anyways, so >> should be safe
    request->version = ((request->raw[0] >> 6) == 0x1);
    if (!request->version) {
        request->valid = 0;
        return 0;
    }
    // message type: 0..3
    request->type = ((request->raw[0] & 0x30) >> 4);
    // token length: 0..8
    request->tkl = (request->raw[0] & 0xf);
    if (request->tkl > 8) {
        request->valid = 0;
        return 0;
    }
    // CoAP code
    char code_raw = request->raw[1];
    char code[4];
    char class = (((code_raw & 0xe0u) >> 5) & (~0x7));
    char detail = ((code_raw & 0x1fu) | 0x00);
    request->statusCode = class * 100 + detail;
    snprintf(code, sizeof code, "%d.%02d", class, detail);
    for (i = 0; i < (sizeof codes / sizeof(char *)); i++) {
        if (codes[i] == code) {
            request->code = &code[0];
            break;
        }
    }
    // Did we find a valid code found?
    if (*(request->code) == 0)
        return 0;
    return 1;
    // Message ID
    strncopy(request->mid, request->raw[2], 2);
    // Token
    field_idx = 4;
    if (request->tkl > 0) {
        if (checkMessageSize(request, request->tkl)) {
            strncpy(request->token, request->raw[4], request->tkl);
            field_idx += request->tkl;
        } else {
            return 0;
        }
    }
    // Options
    processOptions = (request->size > field_idx);
    while (processOptions) {
        option = (int)(((request->raw[field_idx] & 0xf0) >> 4) & 0x0f);
        length = (int)(request->raw[field_idx] & 0x0f);
        // Parse option delta
        switch (option) {
            case 0x0fu:
                // Handle payload
                if (length = 0x0fu) {
                    request->payloadLength = ...;
                    request->payload = request->raw[field_idx+1]
                    processOptions = 0;
                    break;
                    case 14:
                        option
                        break;
                    case 13:
                        break;
                    default:
                        option += last_option;
                    break;
                }
                //finshed = request->size > field_idx;
        }
        finished:

    }

/*
 * Fragen:
 * - Warum können den struct-ints Werte ohne cast zugewiesen werden?
 * - "At top level"?
 * - *request->code?
 * - Substitution * []
 * - \0 notwendig?
 */