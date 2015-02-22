/*
 * Include NS declarations
 */
#include "ns.h"

/*
 * Control debug output
 */
#define DEBUG 1

/*
 * Maximum size (bytes) of a CoAP message as suggested by RFC 7252
 */
#define MAX_COAP_SIZE 1152

/*
 * CoAP headers have a minimum length of four bytes
 */
#define MAX_COAP_CONTENT (MAX_COAP_SIZE - 4)

/*
 * HTTP version to be used in requests
 */
#define HTTP_VERSION "HTTP/1.1"

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
 * Holds the CoAP message and its parameters
 */
typedef struct CoapMsg_s
{
    byte        raw[MAX_COAP_SIZE];  /* holds the raw packet */
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
    Option_t    *options[MAX_COAP_CONTENT];
} CoapMsg_t;

typedef struct HttpReq_s
{
    CoapMsg_t   *coap;           /* Original CoAP request */
    const char  *method;         /* HTTP method code */
    Ns_DString  host;            /* CoAP/HTTP URI host portion  */
    Ns_DString  path;            /* CoAP/HTTP URI path portion  */
    Ns_DString  query;           /* CoAP/HTTP URI query portion */
} HttpReq_t;

static bool LoadMessage(char *file, CoapMsg_t *coap);
static bool ParseCoapMessage(CoapMsg_t *request);
static bool ConstructHttpRequest (HttpReq_t *http);

