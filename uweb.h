// --------------------------------------------------------
// uweb : a minimal web server which compile under MacOS, Linux and Windows
// by Ph. Jounin November 2019
//
// License: GPLv2
// Module: 
//         uweb.h
// --------------------------------------------------------


// ---------------------------------------------------------
// default parameters
// ---------------------------------------------------------

#define DEFAULT_BURST_PKTS    5
#define DEFAULT_BUFLEN       (1448*DEFAULT_BURST_PKTS)    // buffer size for reading HTTP command and file content (2 pkts of 1500 bytes)
char DEFAULT_PORT[] =  "8080"    ;
#define DEFAULT_MAXTHREADS   1024       // maximum simultaneous connections
char DEFAULT_HTMLFILE[] = "index.html"; // if request is "GET / HTTP/1.1"

// is option -c activate default :
const char DEFAULT_BINARY_TYPE[] = "application/octet-stream";
const char DEFAULT_TEXT_TYPE[]   = "text/plain";



// ---------------------------------------------------------
// Error codes and text
// ---------------------------------------------------------
// managed status code
enum     { HTTP_OK=200,
           HTTP_PARTIAL=206,
           HTTP_BADREQUEST=400,
           HTTP_SECURITYVIOLATION=403,
           HTTP_NOTFOUND=404,
           HTTP_METHODNOTALLOWED=405,
           HTTP_TYPENOTSUPPORTED=415,
           HTTP_SERVERERROR=500 };

// requests processed by uweb
enum {    HTTP_GET = 1,
              HTTP_HEAD,  };

// Reporting
struct S_ErrorCodes
{
        int         status_code;
        const char *txt_content;
        const char *html_content;
}
sErrorCodes[] =
{
    { HTTP_BADREQUEST,        "Bad Request",            "HTTP malformed request syntax.",  },
    { HTTP_NOTFOUND,          "Not Found",              "The requested URL was not found on this server.",  },
    { HTTP_SECURITYVIOLATION, "Forbidden",              "Directory traversal attack detected.",             },
    { HTTP_TYPENOTSUPPORTED,  "Unsupported Media Type", "The requested file type is not allowed on this static file webserver.<br>\
                                                         Options -ct or -cb will override this control.", },
    { HTTP_METHODNOTALLOWED,  "Method Not Allowed",     "The requested file operation is not allowed on this static file webserver.", },
    { HTTP_SERVERERROR,       "Internal Server Error",  "Internal Server Error, can not access to file anymore.", },
};

// HTML and HTTP message return on Error
const char szHTMLErrFmt[]  = "<html><head>\n<title>%d %s</title>\n</head><body>\n<h1>%s</h1>\n%s\n</body></html>\n";
const char szHTTPDataFmt[] = "HTTP/1.1 %d %s\nServer: uweb-%s\nContent-Length: %" PRIu64 "\nConnection: close\nContent-Type: %s\n\n";


  // ---------------------------------------------------------
  // Operationnal states : settings, HTML types  and thread data
  // ---------------------------------------------------------

// Set to False if interruption
BOOL GO_ON=TRUE;

const int SELECT_TIMEOUT = 5;  // every 5 seconds, look for terminated threads
const int LISTENING_QUEUE_SIZE = 3; // do not need a large queue

// uweb Settings
struct S_Settings
{
        int   uVerbose;
        BOOL  bIPv4;
        BOOL  bIPv6;
        char  *szPort;
        char  *szBoundTo;
        const char  *szDefaultHtmlFile;
        const char  *szDefaultContentType;      // all files accepted with this content-type
        int    max_threads;             // maximum simultaneous connections
        int    slow_down;               // msec to wait between two frames
}
sSettings = { WARN, FALSE, FALSE, DEFAULT_PORT, NULL,  DEFAULT_HTMLFILE, NULL, DEFAULT_MAXTHREADS, FALSE };

typedef enum e_THREADSTATUS    THREADSTATUS ;
enum e_THREADSTATUS { THREAD_STATE_INIT, THREAD_STATE_RUNNING, THREAD_STATE_EXITING, THREAD_STATE_DOWN };

// The structure for each transfer
struct S_ThreadData
{
        int         request;    // GET or HEAD
        SOCKET      skt;                        // the transfer skt
        SOCKADDR_STORAGE sa;            // keep track of the client
        char       *buf;                        // buffer for communication allocated in main thread
        unsigned    buflen;                     // sizeof this buffer
        char        url_filename[MAX_PATH];     // URL to be retrieved
        char        long_filename[MAX_PATH];    // canonical file name with path
        char       *file_name;                  // pointer inside long_filename
        char       *file_type;                  // pointer inside long_filename
        FILE       *hFile;                      // file handle
        DWORD64     qwFileCurrentPos;           // pos in file (also the number of bytes sent to the client)
        DWORD64     qwFileSize;                 // total size of the file
        time_t      tStartTrf;                  // when the transfer has started

        THREAD_ID   ThreadId;                  // thread data (posix) or Id (Windows)
        THREADSTATUS ThStatus;                  // thread status
        struct S_ThreadData *next;
};


