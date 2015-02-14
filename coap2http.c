// CoAP to HTTP converter, standalone version

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tkDecls.h>

// Maximum size (bytes) of a CoAP message as suggested by RFC 7252
#define MAX_SIZE 1152

// Beginning of declarations (will be moved to .h later)

typedef unsigned char byte;
typedef unsigned char bool;
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
    int     number;
    int     length;
    byte    *value;
} Option_t;
/*
 * Holds the request and its parameters
 */
typedef struct Request_s
{
    byte        raw[MAX_SIZE];  // holds the raw packet
    int         size;           // size in bytes
    int         valid;          // validity of the request
    int         position;       // current parser position
    int         version;        // CoAP version
    int         type;           // message type
    int         tkl;            // token length
    Code_t      *code;          // message code
    byte        *mid;           // message id
    byte        *token;         // token
    byte        *payload;       // payload
    int         payloadLength;  // length of payload
    int         optionCount;    // number of valid options
    Option_t    *options[MAX_SIZE - 4];
} Request_t;

static int loadMessage(char *file, Request_t *request);
static int parseRequest(Request_t *request);

// End of declarations

int main(int argc, char *argv[])
{
    Request_t request = NULL;
    bzero(&request, sizeof(Request_t));
    request.valid = 1;

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
        request->size = (int) fread(request->raw, 1, MAX_SIZE, fd);
        fclose(fd);
        return 1;
    } else
        fprintf(stderr, "File <%s> could not be opened.\n", file);
    return 0;
}

/*
 * Check size of the CoAP message
 */
static bool checkRemainingSize(Request_t *request, int increment)
{
    if ((request->position + increment) > request->size) {
        request->valid = 0;
        return 0;
    }
    return 1;
}

/*
 * Parse the content of a CoAP request
 */
static int parseRequest(Request_t *request) {
    // Loop variable
    int i;
    // Index of next byte to parse
    request->position = 0;
    // Option struct
    Option_t option;
    bzero(&option, sizeof(Option_t));
    // Last option delta
    int lastOptionNumber = 0;
    // Registry of valid CoAP message codes
    int code_registry[] = {
            000, 001, 002, 003, 004,
            201, 202, 203, 204, 205,
            400, 401, 402, 403, 404, 405, 406, 412, 413, 415,
            500, 501, 502, 503, 504, 505
    };
    // CoAP messages can't be shorter than 5 bytes
    if (!checkRemainingSize(request, 4))
        return 0;
    // CoAP version: must be 0b01
    // MSB must be 0 anyways, so >> should be safe
    request->version = ((request->raw[0] >> 6) == 0x1u);
    if (!request->version) {
        request->valid = 0;
        return 0;
    }
    // message type: 0..3
    request->type = ((request->raw[0] & 0x30u) >> 4);
    // token length: 0..8
    request->tkl = (request->raw[0] & 0xfu);
    if (request->tkl > 8) {
        request->valid = 0;
        return 0;
    }
    // CoAP code
    byte code_raw = request->raw[1];
    Code_t code;
    code.class = (((code_raw & 0xe0u) >> 5) & (~0x7u));
    code.detail = ((code_raw & 0x1fu) | 0x00u);
    for (i = 0; i < (sizeof code_registry / sizeof(int)); i++) {
        if (code_registry[i] == (code.class * 100 + code.detail)) {
            request->code = &code;
            break;
        }
    }
    // Did we find a valid code?
    if (request->code == 0)
        return 0;
    // Message ID
    request->mid = &(request->raw[2]);
    // Token
    request->position = 4;
    if (request->tkl > 0) {
        if (checkRemainingSize(request, request->tkl)) {
            request->token = &(request->raw[4]);
            request->position += request->tkl;
        } else {
            return 0;
        }
    }
    // Options
    bool processOptions = checkRemainingSize(request, 1);
    while (processOptions) {
        request->position += 1;
        option.number = (((request->raw[request->position] & 0xf0u) >> 4) & 0x0fu);
        option.length = (request->raw[request->position] & 0x0fu);
        // Parse option delta
        switch (option.number) {
            case 0x0fu:
                // Payload marker or invalid
                switch (option.length) {
                    case 0x0fu:
                        request->payload = &(request->raw[request->position]);
                        request->payloadLength = request->size - request->position;
                        break;
                    default:
                        request->valid = 0;
                        break;
                }
                processOptions = 0;
            case 0x0eu:
                if (checkRemainingSize(request, 2)) {
                    option.number = (int) request->raw[request->position] * 256 + (int) request->raw[request->position + 1] - 269;
                    request->position += 2;
                }
                break;
            case 0x0du:
                if (checkRemainingSize(request, 1)) {
                    option.number = (int) request->raw[request->position ] - 13;
                    request->position += 1;
                }
                break;
            default:
                break;
        }
        // No payload, process length
        if (processOptions) {
            switch (option.length) {
                case 0x0fu:
                    // Invalid
                    request->valid = 0;
                    processOptions = 0;
                case 0x0eu:
                    if (checkRemainingSize(request, 2)) {
                        option.length = (int) request->raw[request->position] * 256 + (int) request->raw[request->position + 1] - 269;
                        request->position += 2;
                    }
                case 0x0du:
                    if (checkRemainingSize(request, 1)) {
                        option.length = (int) request->raw[request->position ] - 13;
                        request->position += 1;
                    }
                default:
                    break;
            }
        }
        option.number += lastOptionNumber;
        lastOptionNumber = option.number;
        if (processOptions) {
            if (option.length > 0) {
                if (checkRemainingSize(request, option.length)) {
                    option.value = &(request->raw[request->position]);
                } else {
                    // Invalid
                    request->valid = 0;
                    processOptions = 0;
                }
            }
        }
        if (processOptions) {
            // Append option to collection
            request->options[request->optionCount] = &option;
            request->optionCount++;
            if (!checkRemainingSize(request, 1)) processOptions = 0;
        }
    }
    return request->valid;
}
/*
 *
 */