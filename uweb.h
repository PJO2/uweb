// --------------------------------------------------------
// uweb : a minimal web server which compile under MacOS, Linux and Windows
// by Ph. Jounin November 2019
//
// License: GPLv2
// Module: 
//         uweb.h
// --------------------------------------------------------


#define UWEB_VERSION "1.7"

#ifndef FALSE
#  define FALSE (0==1)
#  define TRUE  (1==1)
#endif

typedef int BOOL;
// ---------------------------------------------------------
// default parameters
// ---------------------------------------------------------

#define  DEFAULT_BURST_PKTS      5
#define  DEFAULT_BUFLEN         (1448*DEFAULT_BURST_PKTS)    // buffer size for reading HTTP command and file content (2 pkts of 1500 bytes)
#define  DEFAULT_PORT            "8080"    
#define  DEFAULT_MAXTHREADS     1024       // maximum simultaneous connections
#define  DEFAULT_HTMLFILE       "index.html" // if request is "GET / HTTP/1.1"
#define  DEFAULT_BINARY_TYPE     "application/octet-stream"
#define  DEFAULT_TEXT_TYPE       "text/plain"


#define  SELECT_TIMEOUT        5      // every 5 seconds, look for terminated threads
#define  LISTENING_QUEUE_SIZE  3      // do not need a large queue


// ---------------------------------------------------------
// sSettings is a global variable
// ---------------------------------------------------------
// uweb Settings
struct S_Settings
{
        int   uVerbose;
        BOOL  bIPv4;
        BOOL  bIPv6;
        char  *szPort;
        char  *szBoundTo;
        char  *szDirectory;
        const char  *szDefaultHtmlFile;
        const char  *szDefaultContentType;      // all files accepted with this content-type
        int    max_threads;             // maximum simultaneous connections
        int    slow_down;               // msec to wait between two frames
};
extern struct S_Settings sSettings;
// sSettings = { WARN, FALSE, FALSE, DEFAULT_PORT, NULL, ".", DEFAULT_HTMLFILE, NULL, DEFAULT_MAXTHREADS, FALSE };


// ---------------------------------------------------------
// Arduino-like behavior
// ---------------------------------------------------------

int Setup(void);
void doLoop(void);
void Cleanup(void);

