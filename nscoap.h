/* Include NS declarations */
#include "ns.h"

/* Version of this plugin */
#define NSCOAP_VERSION "0.1"

/* Control debug output */
#define DEBUG 1

/* Maximum size (bytes) of a CoAP message as suggested by RFC 7252 */
#define MAX_COAP_SIZE 1152

/* Maximum size of a packet that's read from file. */
#define MAX_PACKET_SIZE 16384

/* Fallback value as per RFC 7252 section 4.6 */
#define MAX_COAP_CONTENT 1024

/* HTTP version to be used in requests */
#define HTTP_VERSION "HTTP/1.0"

typedef unsigned char byte;

/* Message code details */
typedef struct Code_s
{
    unsigned int     class;
    unsigned int     detail;
} Code_t;

typedef struct Option_s
{
    unsigned int delta;
    unsigned int length;
    unsigned int number;
    byte        *value;
} Option_t;

/* Holds the CoAP message and its parameters */
typedef struct CoapMsg_s
{
    bool         valid;          /* validity of the message */
    unsigned int version;        /* CoAP version */
    unsigned int type;           /* message type */
    size_t       tokenLength;    /* token length */
    unsigned int codeValue;      /* message code */
    unsigned int messageID;      /* message id */
    byte         token[8];       /* token */
    unsigned int contentFormat;  /* Content-Format RFC 7252 sect 5.10 */
    byte        *payload;        /* payload */
    size_t       payloadLength;  /* length of payload */
    int          optionCount;    /* number of valid options */
    Option_t    *options[MAX_COAP_CONTENT];
} CoapMsg_t;

typedef struct HttpReq_s
{
    const char *method;         /* HTTP method code */
    Ns_DString  token;          /* CoAP token */
    Ns_DString  host;           /* CoAP/HTTP URI host portion  */
    Ns_DString  path;           /* CoAP/HTTP URI path portion  */
    Ns_DString  query;          /* CoAP/HTTP URI query portion */
    const char *contentType;    /* HTTP Content-Type */
    byte       *payload;        /* pointer to beginning of payload */
    size_t      payloadLength;  /* length of payload in bytes */
} HttpReq_t;

typedef struct HttpRep_s
{
    unsigned int  status;                 /* HTTP status code */
    Ns_Set       *headers;                /* HTTP headers */
    byte         *payload;                /* pointer to beginning of payload */
    size_t        payloadLength;          /* length of payload in bytes */
} HttpRep_t;

/* Raw packet bytes (L4 payload) */
typedef struct Packet_s
{
    byte       *raw;                    /* holds the raw packet bytes */
    size_t      position;               /* current parser position */
    size_t      size;                   /* size in bytes */
} Packet_t;

/* Driver parameters */
typedef struct {
    int placeholder;                    /* currently, we need no "own" parameters,
                                           but empty structs are a non-standard an GNU extension */
} CoapDriver;

/* CoAP parameters (sock->arg) */
typedef struct CoapParams_s
{
    Ns_DString  *sendbuf;                /* buffered respnse waiting to be sent */
    unsigned int type;                   /* message type (for con/ack matching) */
    unsigned int messageID;              /* message ID (for req/ack matching) */
    byte         token[8];               /* CoAP token */
    size_t       tokenLength;            /* token length */
    unsigned int flags;
} CoapParams_t;

#define NSCOAP_FLAG_ALREADY_HANDLED 0x01u

/* Locally defined functions */
static bool SerializeCoap(CoapMsg_t *coap, Packet_t *packet);
static bool ParseCoap(Packet_t *packet, CoapMsg_t *coap, CoapParams_t *params);
static bool Coap2Http(CoapMsg_t *coap, HttpReq_t *http);
static bool Http2Coap(HttpRep_t *http, CoapMsg_t *coap, CoapParams_t *params);

static Ns_DriverListenProc Listen;
static Ns_DriverAcceptProc Accept;
static Ns_DriverRecvProc Recv;
static Ns_DriverSendProc Send;
static Ns_DriverKeepProc Keep;
static Ns_DriverCloseProc Close;
static Ns_TclTraceProc CoapInterpInit;
static Tcl_ObjCmdProc CoapObjCmd;

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
