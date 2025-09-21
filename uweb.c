// --------------------------------------------------------
// uweb : a minimal web server which compile under 
//        MacOS, Linux and Windows
// by Ph. Jounin November 2019
// 
// License: GPLv2
// Sources : 
//              - nweb23.c from IBM and Nigel Griffiths
//              - mweb.cpp from Ph. Jounin
// Pelles C compilation :  
//				Project properties, choose target architecture
//              -Tx86-coff, -machine:x64, LIB C:\Program Files\PellesC\Lib\Win 
//              -Tx64-coff, -machine:x64, LIB C:\Program Files\PellesC\Lib\Win64
// ---------------------------------------------------------



#define _CRT_SECURE_NO_WARNINGS	1
#define _CRT_SECURE_NO_DEPRECATE


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

// avoid warning "variable set but unused"
#define __DUMMY(x) ( (void) (x) )

#define INVALID_FILE_VALUE NULL

// ---------------------------------------------------------
// Windows portability tweaks
// ---------------------------------------------------------

#if defined (_MSC_VER) || defined (__POCC__)


#undef UNICODE

// #include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <strsafe.h>
#include <process.h>

#define snprintf _snprintf 
#define vsnprintf _vsnprintf 
#define strcasecmp _stricmp 
#define strncasecmp _strnicmp 
#define strnlen     strnlen_s

// print 64 bytes unsigned (for files > 4Gb)
#define _FILE_OFFSET_BITS 64
#define PRIu64   "I64u"

typedef  int    socklen_t;

// ---      Common thread encapsulation
typedef HANDLE THREAD_ID;
typedef unsigned THREAD_RET;

#define INVALID_THREAD_VALUE (THREAD_ID) -0

THREAD_ID _startnewthread ( THREAD_RET (WINAPI * lpStartAddress) (void*), 
                            void *lpParameter ) 
{ return (THREAD_ID) _beginthreadex (NULL, 0, lpStartAddress, lpParameter, 0, NULL); }
void _waitthreadend (THREAD_ID ThId)   { WaitForSingleObject(ThId, INFINITE); } 
void _killthread (THREAD_ID ThId)      { TerminateThread (ThId, -1); } 


// millisecond sleep (native for Windows, not for unix)
void ssleep (int msec)                 { Sleep (msec); }

// socket portability
#ifndef SO_REUSEPORT
#  define SO_REUSEPORT 0
#endif

#endif


// ---------------------------------------------------------
// Unix portability tweaks
// ---------------------------------------------------------

#ifdef UNIX

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <signal.h>

#include <pthread.h>


#define WINAPI

typedef int            BOOL;
typedef uint64_t       DWORD64;

// ---      system library
int GetLastError(void)     { return errno; }
#define ERROR_FILE_NOT_FOUND ENOENT
void ssleep (int msec)     { sleep (msec / 1000); usleep ((msec % 1000) * 1000); }
int min(int a, int b)      { return (a < b ? a : b); }


// ----     socket library and types
#define INVALID_SOCKET -1

typedef struct sockaddr_storage SOCKADDR_STORAGE;
typedef struct sockaddr *LPSOCKADDR;
typedef struct addrinfo ADDRINFO;
typedef int SOCKET;
typedef int WSADATA;
#define MAKEWORD(low,high) ( low + (high<<8) )

int closesocket(int s)                   { return close (s); }
int WSAStartup(int version, WSADATA *ws) 
{ 
    // ignore SIGPIPE signal (socket closed), avoid to terminate main thread !!
    signal(SIGPIPE, SIG_IGN);
    return 0; 
}   // 0 is success
int WSACleanup()                         { return 0; }


// ----     strings
#define StringCchPrintf  snprintf
int StringCchCopy(char *d, int n, const char *s)  { strncpy (d, s, n); return 1; }
int CharUpperBuff(char *s, int n)     {int p=0;  while (*s!=0 && n-->0)  { if (islower(*s)) *s=toupper(*s), p++; }  return p; }


// ----     directories
#define MAX_PATH 512

int GetFullPathName(const char *lpFileName, int nBufferLength, char *lpBuffer, char **p)
{
	if ( realpath (lpFileName, lpBuffer) == NULL) 
		return 0;
	if (p!=NULL)   
		*p = strrchr (lpBuffer, '/'); 
	return strlen(lpBuffer);
}

int GetCurrentDirectory (int nBufferLength, char *lpBuffer) 
{
	char *p;
	p = getcwd (lpBuffer, nBufferLength);
	return p==NULL ? 0 : strlen (lpBuffer);
}

int SetCurrentDirectory (const char *lpPathName)  { return chdir (lpPathName)==0; }


// ----     threads
typedef pthread_t THREAD_ID;
typedef void *    THREAD_RET;
#define INVALID_THREAD_VALUE ((THREAD_ID) (-1))

THREAD_ID _startnewthread ( THREAD_RET (WINAPI * lpStartAddress) (void*), void *lpParameter ) 
{
        int rc;
	THREAD_ID ThId;
        rc =   pthread_create (& ThId, NULL, lpStartAddress, lpParameter);
        return rc==0 ? ThId : INVALID_THREAD_VALUE;
}
void _waitthreadend (THREAD_ID id) { pthread_join (id, NULL); }
// void _killthread (THREAD_ID ThId)  { pthread_kill (ThId, SIGINT); } 
int GetExitCodeThread (THREAD_ID ThId, THREAD_RET *rez) { *rez=0 ; return 0; }
int CloseHandle (THREAD_ID ThId)             { return 0; }

#endif

// ---------------------------------------------------------
// end of tweaks 
// ---------------------------------------------------------

#include "log.h"
#include "uweb.h"
#include "html_extensions.h"

  // ---------------------------------------------------------
  // Protocol Error codes and text
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

enum e_THREADSTATUS { THREAD_STATE_INIT, THREAD_STATE_RUNNING, THREAD_STATE_EXITING, THREAD_STATE_DOWN };
typedef enum e_THREADSTATUS    THREADSTATUS ;

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



// Thread database
struct S_ThreadData  *pThreadDataHead;			// array allocated in main
int nbThreads = 0;                      // # running threads


// status passed to logger funcion
enum { LOG_BEGIN, LOG_END, LOG_RESET };


/////////////////////////////////////////////////////////////////
// utilities functions :
//      - report error
/////////////////////////////////////////////////////////////////


// Function LastErrorText. Thread unsafe
// A wrapper for FormatMessage : retrieve the message text for a system-defined error
char *LastErrorText(void)
{
static char szLastErrorText[512];
	// strerror_r (errno, szLastErrorText, sizeof szLastErrorText);
	strncpy (szLastErrorText, strerror (errno), sizeof szLastErrorText);
        szLastErrorText[sizeof szLastErrorText - 1] = 0;
	return szLastErrorText;
} // LastErrorText



  /////////////////////////////////////////////////////////////////
  // utilities socket operations :
  //	 - check that socket is still opened by listen at it
  //	 - return MSS
  //      - bind its socket
  //      - init WSA socket
  //      - Check if IPv6 is enabled
  //      - send HTTP error
  /////////////////////////////////////////////////////////////////

// a Windows wrapper to  call WSAStartup...
int InitSocket()
{
	WSADATA  wsa;
	int      iResult;
	iResult = WSAStartup(MAKEWORD(2, 0), &wsa);
	iResult = 1;
	if (iResult < 0)
	{
		LOG (FATAL, "Error : WSAStartup failed\nError %d (%s)\n", GetLastError(), LastErrorText());
		exit(-1);    // no recovery
	}
	return iResult;
} // InitSocket

int IsTransferCancelledByPeer(SOCKET skt)
{
	struct timeval to = { 0, 0 };
	fd_set fdset;
	char   recv_buf[32]; // read a significant amount of data
                             // since the HTTP request is still in buffer
	int   iResult;
	// check if socket has been closed by client
	FD_ZERO(&fdset);
	FD_SET(skt, &fdset);
	iResult = select(0, &fdset, NULL, NULL, &to)>0
		&& recv(skt, recv_buf, sizeof recv_buf, MSG_PEEK) == 0;
	return iResult;
} // IsTransferCancelledByPeer


  // return the max segment size for this socket
int GetSocketMSS(SOCKET skt)
{
	int tcp_mss = 0;
	unsigned  opt_len = sizeof tcp_mss;
	int iResult;

	iResult = getsockopt(skt, IPPROTO_TCP, TCP_MAXSEG, (char*) & tcp_mss , & opt_len);
	if (iResult < 0)
	{
		LOG (FATAL, "Failed to get TCP_MAXSEG for master socket.\nError %d (%s)\n", 
                           GetLastError(), LastErrorText());
		return -1;
	}
	return tcp_mss;
} // GetSocketMSS


  // return TRUE IPv6 is enabled on the local system
BOOL IsIPv6Enabled(void)
{
	SOCKET s = INVALID_SOCKET;
	int Rc;
	// just try to open an IPv6 socket
	s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	Rc = GetLastError();  // should be WSAEAFNOSUUPORT 10047
	closesocket(s);
        __DUMMY(Rc);

	return s != INVALID_SOCKET;
} // IsIPv6Enabled

  // debug
int dump_addrinfo(ADDRINFO *runp)
{
	char hostbuf[50], portbuf[10];
	int e;

        LOG (INFO, "family: %d, socktype: %d, protocol: %d, ", runp->ai_family, runp->ai_socktype, runp->ai_protocol);
	e = getnameinfo(
			runp->ai_addr, runp->ai_addrlen,
			hostbuf, sizeof(hostbuf),
			portbuf, sizeof(portbuf),
			NI_NUMERICHOST | NI_NUMERICSERV
	);
	LOG (WARN, "host: %s, port: %s\n", hostbuf, portbuf);
       __DUMMY(e);
return 0;
}


// create a listening socket
// and bind it to the HTTP port
SOCKET BindServiceSocket(const char *port, const char *sz_bind_addr)
{
	SOCKET             sListenSocket = INVALID_SOCKET;
	int                Rc;
	ADDRINFO           Hints, *res, *cur;
	int                True = 1;

	memset(&Hints, 0, sizeof Hints);
	if (sSettings.bIPv4)     	Hints.ai_family = AF_INET;   // force IPv4
	else if (sSettings.bIPv6)  	Hints.ai_family = AF_INET6;   // force IPv6
	else                            Hints.ai_family = AF_UNSPEC;    // use IPv4 or IPv6, whichever

	// resolve the address and port we want to bind the server
	Hints.ai_socktype = SOCK_STREAM;
	Hints.ai_flags = AI_PASSIVE;     // fill in my IP for me
	Rc = getaddrinfo(sz_bind_addr, port, &Hints, &res);
	if (Rc != 0)
	{
		LOG (ERROR, "Error : specified address %s is not recognized\nError %d (%s)\n", 
			  sz_bind_addr, GetLastError(), LastErrorText());
		return INVALID_SOCKET;
	}

	// if getaddr_info returns only one entry: take it (option -i, -4, -6 or ipv4 only host)
	// else search for  the ipv6 socket (then deactivate the option IPV6_V6ONLY)
	if (res->ai_next == NULL)   cur = res;
	else                        for (cur = res ; cur!=NULL  &&  cur->ai_family!=AF_INET6 ; cur = cur->ai_next);
	assert (cur!=NULL);

	if (sSettings.uVerbose) dump_addrinfo (cur);

	// now open socket based on either selection
	sListenSocket = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
	if (sListenSocket == INVALID_SOCKET)
	{
		LOG (ERROR, "Error : Can't create socket\nError %d (%s)\n", GetLastError(), LastErrorText());
		return INVALID_SOCKET;
	}

	// now allow both IPv6 and IPv4 by disabling IPV6_ONLY (necessary since Vista)
	// http://msdn.microsoft.com/en-us/library/windows/desktop/bb513665(v=vs.85).aspx
	// does not work under XP --> do not check return code
	if (res->ai_next != NULL)  // did we select the ipv6 entry ?
	{
		int Param = FALSE;
		Rc = setsockopt(sListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)& Param, sizeof Param);
	}

	// allow socket to be reopened quickly
	Rc = setsockopt(sListenSocket, SOL_SOCKET, SO_REUSEPORT | SO_REUSEADDR, (char*)& True, sizeof True);
	if (Rc == INVALID_SOCKET)
	{
		LOG (WARN, "Error : Can't not activate reuse mode, will continue anymay\nError %d (%s)\n",
		          GetLastError(), LastErrorText());
	}

	// bind the socket to the active interface
	Rc = bind(sListenSocket, cur->ai_addr, cur->ai_addrlen);
	if (Rc == INVALID_SOCKET)
	{
		LOG (ERROR, "Error : Can't not bind socket\nError %d (%s)\n", GetLastError(), LastErrorText());
		closesocket(sListenSocket);
		return INVALID_SOCKET;
	}

	// create the listen queue
	Rc = listen(sListenSocket, LISTENING_QUEUE_SIZE);
	if (Rc == -1)
	{
		LOG (ERROR, "Error : on listen\nError %d (%s)\n", GetLastError(), LastErrorText());
		closesocket(sListenSocket);
		return INVALID_SOCKET;
	}

	freeaddrinfo(res);
	return   Rc == INVALID_SOCKET ? Rc : sListenSocket;
} // BindServiceSocket




  /////////////////////////////////////////////////////////////////
  // HTTP protocol management
  //      - decode incoming message
  //      - read file and send it through the Http channel
  // resources are freed by calling thread
  /////////////////////////////////////////////////////////////////

// util: send an pre formated error code
int HTTPSendError(SOCKET skt, int HttpStatusCode)
{
        char szContentBuf[512], szHTTPHeaders[256];
        int  ark;
        int  iResult;

        // search error code in sErrorCodes array
        for ( ark=0 ; sErrorCodes[ark].status_code != 0  && sErrorCodes[ark].status_code!=HttpStatusCode ; ark++ );
        assert (sErrorCodes[ark].status_code==HttpStatusCode);  // exit if error code not found (bug)

        StringCchPrintf (szContentBuf, sizeof szContentBuf, szHTMLErrFmt,
                 	sErrorCodes[ark].status_code,
                	sErrorCodes[ark].txt_content,
                	sErrorCodes[ark].txt_content,
                	sErrorCodes[ark].html_content );
        // now we have the string, get its length and send headers and string
        StringCchPrintf (szHTTPHeaders, sizeof szHTTPHeaders, szHTTPDataFmt,
                	sErrorCodes[ark].status_code,
                	sErrorCodes[ark].txt_content,
                	UWEB_VERSION,
                	(DWORD64) strlen (szContentBuf),
                	"text/html" );
        iResult = send (skt, szHTTPHeaders, strlen (szHTTPHeaders), 0);
        iResult = send (skt, szContentBuf,  strlen (szContentBuf),  0);
        return iResult;
} // HTTPSendError


  // a minimal reporting for the server side
int LogTransfer(const struct S_ThreadData *pData, int when, int http_status)
{
	char szAddr[INET6_ADDRSTRLEN], szServ[NI_MAXSERV];
	int Rc;

	if (sSettings.uVerbose==0)  return 0;

	strcpy (szAddr, "");
	strcpy (szServ, "");
	Rc = getnameinfo((LPSOCKADDR)& pData->sa, sizeof pData->sa,
			szAddr, sizeof szAddr,
			szServ, sizeof szServ,
			NI_NUMERICHOST | NI_NUMERICSERV);
	if (Rc!=0) 
	{
		errno = Rc;
		LOG (ERROR, "getnameinfo failed.\nError %d (%s)\n", Rc, LastErrorText());
                return -1;
	}
	// do not use ipv4 mapped address
	if (* (unsigned short *) szAddr == * (unsigned short *) "::")
		memmove (szAddr, & szAddr[sizeof "::ffff:" - 1], sizeof "255.255.255.255");

	switch (when)
	{
	    case LOG_BEGIN:
                LOG (DEBUG, "uweb answers with headers:\n--->>\n%s--->>\n", pData->buf);
                LOG (WARN, "From %s:%s, GET %s, MSS is %u, burst size %d\n", 
			szAddr, szServ, pData->file_name, GetSocketMSS(pData->skt), pData->buflen);
		break;

    	    case LOG_END:
                LOG (WARN, "From %s:%s, GET %s: %" PRIu64 " bytes sent, status : %d, time spent %lus\n",
			szAddr, szServ, pData->file_name==NULL ? "unknown" : pData->file_name,
			pData->qwFileCurrentPos, http_status, 
			time(NULL) - pData->tStartTrf
		);
		break;
    	    case LOG_RESET:
		LOG (WARN, "GET %s: Reset by %s:%s, %" PRIu64 " bytes sent, status : %d, time spent %lus\n",
			pData->file_name==NULL ? "unknown" : pData->file_name,  
                        szAddr, szServ, 
			pData->qwFileCurrentPos, http_status,
			time(NULL) - pData->tStartTrf
		);
		break;
	}
return 0;
} // LogTransfer



  // translate file extension into HTTP content-type field
  // Get extension type 
const char *GetHtmlContentType(const char *os_extension)
{
	int ark;

	if (os_extension == NULL)  
		return  sSettings.szDefaultContentType;

	// search for extension (do case insentive matching even for unix)
	for (ark = 0; ark<sizeof(sHtmlTypes) / sizeof(sHtmlTypes[0]); ark++)
		if (strcasecmp (sHtmlTypes[ark].ext, os_extension) == 0) break;
	if (ark >= sizeof(sHtmlTypes) / sizeof(sHtmlTypes[0]))
	{
		if (sSettings.szDefaultContentType==NULL)
		    LOG (WARN, "Unregistered file extension\n");
		return sSettings.szDefaultContentType;		// NULL if not overridden
	}
	return (char *) sHtmlTypes[ark].filetype;
} // GetHtmlContentType


  // extract the file name 
  //			1- do not crash if we receive misformatted packets
  // HTTP formatting is GET _space_ file name ? arguments _space_ HTTP/VERSION _end of line_
BOOL ExtractFileName(const char *szHttpRequest, int request_length, char *szFileName, int name_size)
{
	const char *pCur=NULL, *pEnd;
	int         len, url_length;

	// check that string is nul terminated (ok already done in caller)
	if (strnlen(szHttpRequest, request_length) == request_length)
		return FALSE;

	// check that request is long enough to find the file name
	if (request_length < sizeof "GET / HTTP/1.x\n" - 1) return FALSE;


	// search second word (first has already been decoded) and space has been checked
	for (pCur = szHttpRequest; *pCur != ' '; pCur++);  // skip first word
	for (; *pCur == ' '; pCur++);  // go to second word

	// file name is supposed to start with '/', anyway accepts if / is missing
	for (; *pCur == '/'; pCur++);  // skip  /

	// go to next work or '?' or end of line (missing HTTP version)
	pEnd = strpbrk(pCur, "\r\n ?");
	// add: check that pEnd is not NULL !
	if ( pEnd==NULL || (*pEnd != ' ' && *pEnd != '?') )		// if anormal endings
	{
		return FALSE;
	}
	// now we ignore all the other stuff sent by client....
	// just copy the file name
	url_length = (int) (pEnd - pCur);
	if (url_length == 0)		// file name is /
		StringCchCopy(szFileName, name_size, sSettings.szDefaultHtmlFile);
	else
	{
		len = min(url_length, name_size - 1);
		memcpy(szFileName, pCur, len);
		szFileName[len] = 0;
	}
	return TRUE;
} // ExtractFileName



  // Read request and extract file name
  // if error, can return abruptely: resources freed in calling funtions
int DecodeHttpRequest(struct S_ThreadData *pData, int request_length)
{
	char     szCurDir[MAX_PATH];

	// double check buffer overflow
	if (request_length >= (int)pData->buflen)
		exit(-2);
	pData->buf[request_length++] = 0;

	// dump complete request
        LOG (DEBUG, "client request:\n<<---\n%s<<---\n", pData->buf);

	// ensure request is a GET or HEAD
	CharUpperBuff(pData->buf, sizeof "GET " - 1);
	if (memcmp(pData->buf, "GET ", sizeof "GET " - 1) == 0)
		pData->request = HTTP_GET;
	else if (memcmp(pData->buf, "HEAD ", sizeof "HEAD " - 1) == 0)
		pData->request = HTTP_HEAD;
	else  // reject other requests !
	{
		LOG (WARN, "Only Simple GET and HEAD operations supported\n");
		return HTTP_METHODNOTALLOWED;
	}
	// extract file name
	if (!ExtractFileName(pData->buf, request_length, pData->url_filename, sizeof pData->url_filename))
	{
		LOG (WARN, "invalid HTTP formatting\n");
		return HTTP_BADREQUEST;
	}

        // dry-run : try to open it (sanaty checks not done)
	pData->hFile = fopen (pData->url_filename, "rb");
        if (pData->hFile==INVALID_FILE_VALUE)   
        {
                LOG (WARN, "file %s not found/access denied\n", pData->url_filename);
                return HTTP_NOTFOUND;
        }
        fclose (pData->hFile);
        pData->hFile=INVALID_FILE_VALUE;

	// get canonical name && locate the file name location
	// Valid since we are in the main thread
	if ( ! GetFullPathName(pData->url_filename, MAX_PATH, pData->long_filename, &pData->file_name) )
        {
                if (GetLastError()==ERROR_FILE_NOT_FOUND)   
                        LOG (WARN, "File |%s| not found\n", pData->url_filename);
                else    LOG (WARN, "s: invalid File formatting\n", pData->url_filename);
		pData->file_name = NULL;
                return HTTP_BADREQUEST;
        }

	if (pData->file_name == NULL)
		pData->file_type = NULL;
	else
		pData->file_type = strrchr(pData->file_name, '.');	// search for '.'

									// sanity check : do not go backward in the directory structure
	GetFullPathName(".", MAX_PATH, szCurDir, NULL);
#ifdef UNSAFE__DEBUG
	LOG(TRACE, "file to be retreived is %s, path is %s, file is %s, cur dir is %s\n", pData->long_filename, pData->buf, pData->file_name, szCurDir);
#endif
	if (memcmp(szCurDir, pData->long_filename, strlen(szCurDir)) != 0)
	{
		LOG (WARN, "directory traversal detected\n");
		return HTTP_SECURITYVIOLATION;
	}
	return HTTP_OK;
} // DecodeHttpRequest



// Thread base
THREAD_RET WINAPI HttpTransferThread(void * lpParam)
{
	int      bytes_rcvd;
	int      bytes_read, bytes_sent;
	const char     *pContentType;
	struct S_ThreadData *pData = (struct S_ThreadData *)  lpParam;
	int      iHttpStatus=HTTP_BADREQUEST;
	int      tcp_mss;

	pData->ThStatus = THREAD_STATE_RUNNING;   // thread is now running

        // read http request
	bytes_rcvd = recv(pData->skt, pData->buf, pData->buflen - 1, 0);
	if (bytes_rcvd < 0)
	{
		LOG (ERROR, "Error in recv\nError %d (%s)\n", GetLastError(), LastErrorText());
		goto cleanup;
	}
	// modify buffer size depending on MSS
	if ( (tcp_mss = GetSocketMSS(pData->skt)) > 0 ) 
        {
		pData->buflen = DEFAULT_BURST_PKTS * tcp_mss;
                pData->buf = realloc (pData->buf, pData->buflen);
                if (pData->buf==NULL)
                { LOG (FATAL, "can not allocate memory\n"); 
                  exit(3); }
        }
               

	// request is valid and pData filled with requested file
	iHttpStatus = DecodeHttpRequest(pData, bytes_rcvd);
	if (iHttpStatus != HTTP_OK)
		goto cleanup;

	// check extension and get the HTTP content=type of the file
	pContentType = GetHtmlContentType(pData->file_type);
	if (pContentType == NULL) 
	{
		iHttpStatus = HTTP_TYPENOTSUPPORTED;
		goto cleanup;
	}

	// open file in binary mode (file length and bytes sent will match)
	pData->hFile = fopen (pData->long_filename, "rb");
	if (pData->hFile == INVALID_FILE_VALUE)
	{
		LOG (ERROR, "Error opening file %s\nError %d (%s)\n", 
                             pData->long_filename, GetLastError(), LastErrorText());
		iHttpStatus = HTTP_NOTFOUND;
		goto cleanup;
	}
	// Get  file size, by moving to the end of file
	fseek (pData->hFile, 0, SEEK_END);
	pData->qwFileSize = ftell (pData->hFile);
	fseek (pData->hFile, 0, SEEK_SET);


	// file accepted -> send HTTP 200 answer
	StringCchPrintf(pData->buf, pData->buflen,
		szHTTPDataFmt,
		HTTP_OK, "OK",
		UWEB_VERSION,
		pData->qwFileSize,
		pContentType);
	send(pData->skt, pData->buf, strlen(pData->buf), 0);
	LogTransfer(pData, LOG_BEGIN, 0);

	if (pData->request == HTTP_GET)
	{
		iHttpStatus = HTTP_PARTIAL;
		do
		{
			bytes_read = fread(pData->buf, 1, pData->buflen, pData->hFile);
			bytes_sent = send(pData->skt, pData->buf, bytes_read, 0);
			pData->qwFileCurrentPos += bytes_read;

			if (pData->buflen == bytes_read && IsTransferCancelledByPeer(pData->skt))
			{
				LogTransfer(pData, LOG_RESET, HTTP_PARTIAL);
				break;
			}
			LOG(TRACE, "read %d bytes from %s\n", bytes_read, pData->long_filename);

			if (sSettings.slow_down) ssleep(sSettings.slow_down);
		} while (bytes_read > 0);

		if (bytes_read == 0 && !feof(pData->hFile))	//note: if transfer cancelled report OK anyway
		{
			LOG (ERROR, "Error in ReadFile\nError %d (%s)\n", GetLastError(), LastErrorText());
			iHttpStatus = HTTP_SERVERERROR;
			goto cleanup;
		}
	} // HTTP GET request
	// if we reach this point file was successfully sent
	iHttpStatus = HTTP_OK;

	__DUMMY(bytes_sent);

cleanup:
	if (pData->skt != INVALID_SOCKET)
	{
		if (iHttpStatus >= HTTP_BADREQUEST)   
			HTTPSendError (pData->skt, iHttpStatus);
		closesocket(pData->skt);
		pData->skt = INVALID_SOCKET;
	}
	if (pData->buf != NULL)
	{
		free(pData->buf);
		pData->buf = NULL;
	}
	if (pData->hFile != INVALID_FILE_VALUE)
	{
		fclose (pData->hFile);
		pData->hFile = INVALID_FILE_VALUE;
	}
	// return Error to client
	LogTransfer(pData, LOG_END, iHttpStatus);
	ssleep(1000);

	pData->ThStatus = THREAD_STATE_EXITING;
	return (THREAD_RET) 0;  // return NULL to please compiler

} // HttpTransferThread



  /////////////////////////////////////////////////////////////////
  // main thread
  //      - create the listening socket
  //      - loop on waiting for incoming connection
  //      - start a new thread for each connection
  //      - free thread resource  after termination
  //      - maintain threads data link list
  /////////////////////////////////////////////////////////////////



  // Do Some cleanup on terminated Threads (use pThreadDataHead as global)
int ManageTerminatedThreads (void)
{
	int ark=0;
	struct S_ThreadData *pCur, *pNext, *pPrev;

	// check if threads have ended and free resources
	for (pPrev=NULL, pCur=pThreadDataHead ;  pCur!=NULL ; pCur=pNext )
	{
		pNext = pCur->next;   // pCur may be freed

		if (pCur->ThStatus==THREAD_STATE_EXITING)
		{
			// wait until thread termination
			_waitthreadend (pCur->ThreadId);
			pCur->ThStatus = THREAD_STATE_DOWN;

			// free resources (if not done before)
			if (pCur->buf!=NULL)    free (pCur->buf), pCur->buf=NULL;
			if (pCur->hFile!=INVALID_FILE_VALUE)  
                                              fclose (pCur->hFile), pCur->hFile=INVALID_FILE_VALUE;
			CloseHandle (pCur->ThreadId);
			ark++;

			// detach pCur from list, then free memory
			if (pPrev==NULL)   pThreadDataHead = pCur->next;
			else               pPrev->next     = pCur->next;
			// free record 
			free (pCur);

			--nbThreads;
		}
		else
		     pPrev=pCur ; // pPrev is the last valid entry
	}
	return ark;
} // ManageTerminatedThreads


THREAD_ID StartHttpThread (SOCKET ClientSocket, const SOCKADDR_STORAGE *sa)
{
	struct S_ThreadData *pCur;

	// resources available ? 
	if (nbThreads >= sSettings.max_threads)
	{
		LOG (WARN, "request rejected: too many simultaneous transfers\n");
                return INVALID_THREAD_VALUE;
	}
	else
	{
		for (pCur=pThreadDataHead ; pCur!=NULL ; pCur=pCur->next);
		// create a new ThreadData structure and populate it
		pCur = (struct S_ThreadData *) calloc (1, sizeof *pCur);
		if (pCur == NULL)
                {
			LOG (FATAL, "can not allocate memory\n");
                        exit(2);
                }

		// populate record
		pCur->ThStatus = THREAD_STATE_INIT ; // thread pregnancy
		pCur->sa = * sa;
		pCur->buflen = DEFAULT_BUFLEN;
		pCur->buf = (char *) malloc (pCur->buflen);
		pCur->skt = ClientSocket;
		pCur->qwFileCurrentPos = 0;
		time(& pCur->tStartTrf);
                pCur->hFile = INVALID_FILE_VALUE;

		if (pCur->buf == NULL)
                {
			LOG (FATAL, "can not allocate memory\n");
                        exit(2);
                }

		// Pass the socket id to a new thread and listen again
		pCur->ThreadId = _startnewthread (HttpTransferThread, (void *) pCur);
		if (pCur->ThreadId == INVALID_THREAD_VALUE)
		{
			LOG (ERROR, "can not allocate thread\n");
			free (pCur->buf);
			free (pCur);
		}
		else
		{
			// insert data at the head of the list
			pCur->next = pThreadDataHead;
			pThreadDataHead = pCur;
			// register thread !
			nbThreads++;
		}
	} // slot available
return pCur->ThreadId;
} // StartHttpThread



// -------------------
// main loop 
// -------------------

static SOCKET ListenSocket;

void doLoop (void)
{
	SOCKADDR_STORAGE sa;
	socklen_t        sa_len;
	SOCKET           ClientSocket;
        struct timeval   tv_select;
        int 		 Rc;
	THREAD_ID	 NewThread;
        fd_set           readfs;
        

        // block main thread on select (wake up every 5 seconds to free resources)
        do
        {
	     // worry about terminated threads
	     ManageTerminatedThreads ();

	     // and listen incoming connections
             FD_ZERO (&readfs);
             FD_SET (ListenSocket, &readfs);
             tv_select.tv_sec  = SELECT_TIMEOUT;   // may have been changed by select
             tv_select.tv_usec = 0; 
             Rc = select (ListenSocket+1, & readfs, NULL, NULL, & tv_select);
        }
        while (Rc==0);  // 0 is timeout

	if (Rc == INVALID_SOCKET) {
		LOG (FATAL, "Error : Select failed\nError %d (%s)\n", GetLastError(), LastErrorText());
		closesocket(ListenSocket);
		WSACleanup();
		exit(1);
	}

	// Accept new client connection (accept will not block)
	sa_len = sizeof sa;
	memset(&sa, 0, sizeof sa);
	ClientSocket = accept(ListenSocket, (struct sockaddr *) & sa, &sa_len);
	if (ClientSocket == INVALID_SOCKET) {
		LOG (FATAL, "Error : Accept failed\nError %d (%s)\n", GetLastError(), LastErrorText());
		closesocket(ListenSocket);
		WSACleanup();
		exit(1);
	}

        // if main thread is awaken : start a new thread, check if a thread has terminated
        // and return listening for incoming connections
        NewThread = StartHttpThread (ClientSocket, & sa);
	// pause either to let thread start or to pause the main loop on error
        ssleep (NewThread== INVALID_THREAD_VALUE ? 1000 : 10);

} // doLoop


// -------------------
// Setup and Cleanup
// -------------------
BOOL Setup (void)
{
char sbuf[MAX_PATH];


        InitSocket();
        ListenSocket = BindServiceSocket (sSettings.szPort, sSettings.szBoundTo);
        if (ListenSocket == INVALID_SOCKET)
             return FALSE;

	if (!SetCurrentDirectory (sSettings.szDirectory))
        {
               LOG (FATAL, "can not change directory to %s\nError %d (%s)\n",
                           sSettings.szDirectory,
                           GetLastError(), LastErrorText());
               return FALSE;
        }
        GetCurrentDirectory(sizeof sbuf, sbuf);
        LOG (WARN, "uweb is listening on port %s, base directory is %s\n",      sSettings.szPort, sbuf);

        return TRUE;
} // Setup 


void Cleaup (void)
{
       ManageTerminatedThreads (); // free terminated threads resources
       closesocket(ListenSocket);
       WSACleanup();
}

