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
 * Maximum size (bytes) of a HTTP reply (needs definition)
 */
#define MAX_HTTP_SIZE 1152

/*
 * Maximum size of a packet that's read from file.
 */
#define MAX_PACKET_SIZE 1152

/*
 * CoAP headers have a minimum length of four bytes
 */
#define MAX_COAP_CONTENT (MAX_COAP_SIZE - 4)

/*
 * HTTP version to be used in requests
 */
#define HTTP_VERSION "HTTP/1.1"

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
    bool        valid;          /* validity of the message */
    int         version;        /* CoAP version */
    int         type;           /* message type */
    size_t      tokenLength;    /* token length */
    int         codeValue;      /* message code */
    int         messageID;      /* message id */
    byte       *token;         /* token */
    byte       *payload;       /* payload */
    int         payloadLength;  /* length of payload */
    int         optionCount;    /* number of valid options */
    Option_t   *options[MAX_COAP_CONTENT];
} CoapMsg_t;

typedef struct HttpReq_s
{
    const char *method;         /* HTTP method code */
    Ns_DString  token;           /* CoAP token */
    Ns_DString  host;            /* CoAP/HTTP URI host portion  */
    Ns_DString  path;            /* CoAP/HTTP URI path portion  */
    Ns_DString  query;           /* CoAP/HTTP URI query portion */
} HttpReq_t;

typedef struct HttpRep_s
{
    int         status;                 /* HTTP status code */
    Ns_Set     *headers;                /* HTTP headers */
    byte       *payload;                /* pointer to beginning of payload */
    int         payloadLength;          /* length of payload in bytes */
} HttpRep_t;

/*
 * Raw packet bytes (L4 payload)
 */
typedef struct Packet_s
{
    byte        raw[MAX_PACKET_SIZE];   /* holds the raw packet bytes */
    int         position;               /* current parser position */
    int         size;                   /* size in bytes */
} Packet_t;

static bool ConstructCoapMessage(CoapMsg_t *coap, Packet_t *packet);
static bool ConstructHttpRequest (HttpReq_t *http, Packet_t *packet);
static bool LoadPacketFromFile(char *file, Packet_t *packet);
static bool ParseCoapMessage(Packet_t *packet, CoapMsg_t *coap);
static bool ParseHttpReply (Packet_t *packet, HttpRep_t *http);
static bool TranslateCoap2Http(CoapMsg_t *coap, HttpReq_t *http);
static bool TranslateHttp2Coap(HttpRep_t *http, CoapMsg_t *coap);
static bool WritePacketToFile(Packet_t *packet, char *file);
static CoapMsg_t *InitCoapMsg(void);
static void FreeCoapMsg(CoapMsg_t *coap);
