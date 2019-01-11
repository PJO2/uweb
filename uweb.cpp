// --------------------------------------------------------
// uweb : a minimal web server based on nweb23.c
// by Ph. Jounin jan 2019
// 
// Sources : 
//              - nweb23.c from IBM and Nigel Griffiths
//              - uweb.cpp from Ph. Jounin
// ---------------------------------------------------------




#define MWEB_VERSION "1.1"

const char SYNTAX[] = ""
"uweb: Usage\n"
"\n mweb [-4] [-6] [-p port] [-d dir] [-i addr] [-c content-type]"
"\n      [-s max connections] [-verbose]\n"
"\n      -4   IPv4 only"
"\n      -6   IPv6 only"
"\n      -c   content-type assigned to unknown files"
"\n           (default: reject unregistered types)"
"\n      -d   base directory for content (default is current directory)"
"\n      -i   listen only this address"
"\n      -p   HTTP port (defaut is 8080)"
"\n      -s   maximum simultaneous connection (default is 1024)"
"\n      -v   verbose"
"\n";

#define _CRT_SECURE_NO_WARNINGS	1
#define _CRT_SECURE_NO_DEPRECATE


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <assert.h>


// ---------------------------------------------------------
// Windows portability tweaks
// ---------------------------------------------------------

#ifdef _MSC_VER


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

#define _FILE_OFFSET_BITS 64
typedef HANDLE THREAD_ID;
typedef unsigned THREAD_RET;

#define INVALID_FILE_VALUE NULL
#define INVALID_THREAD_VALUE (THREAD_ID) -1L

BOOL IsThreadAlive (THREAD_ID ThId)    { return   WaitForSingleObject(ThId, 0) == WAIT_OBJECT_0 ; }
void ssleep (int ssec)                 { Sleep (ssec * 1000); }


#endif


// ---------------------------------------------------------
// Unix portability tweaks
// ---------------------------------------------------------

#ifdef UNIX

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pthread.h>



#define WINAPI
#define INVALID_FILE_VALUE    NULL
#define __cdecl

typedef int BOOL;
typedef int HANDLE;
typedef long long DWORD64;
typedef long int DWORD;
enum { FALSE=0, TRUE };

int GetLastError(void)     { return errno; }
void ssleep (int ssec)     { sleep (ssec); }
int min(int a, int b)      { return (a < b ? a : b); }


// ----     socket library 
#define INVALID_SOCKET -1

typedef struct sockaddr_storage SOCKADDR_STORAGE;
typedef struct sockaddr *LPSOCKADDR;
typedef struct addrinfo ADDRINFO;
typedef int SOCKET;
typedef int WSADATA;
#define MAKEWORD(low,high) ( low + high<<8 )

int closesocket(int s)                   { close (s); }
int WSAStartup(int version, WSADATA *ws) { return 0; }   // 0 is success
int WSACleanup()                         { return 0; }


// ----     strings
#define StringCchPrintf  snprintf
int StringCchCopy(char *d, int n, const char *s)  { strncpy (d, s, n); return 1; }
int CharUpperBuff(char *s, int n)     {int p=0;  while (*s!=0 && n-->0)  { if (islower(*s)) *s=toupper(*s), p++; }  return p; }


// ----     directories
#define MAX_PATH 512

int GetFullPathName(const char *lpFileName, int nBufferLength, char *lpBuffer, char **p)
{
	int Rc;
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

int SetCurrentDirectory (const char *lpPathName)  { return chdir (lpPathName); }


// ----     threads
typedef pthread_t THREAD_ID;
typedef void *    THREAD_RET;
#define INVALID_THREAD_VALUE ((THREAD_ID) (-1))

THREAD_ID beginthreadex (void *security, unsigned stack_size,  THREAD_RET (* lpStartAddress) (void*), void *lpParameter, unsigned init_flag, THREAD_ID *pThId)
{ 
	int rc;
	assert (security==NULL);
	assert (stack_size == 0);
	assert (init_flag == 0);
	rc =  pthread_create (pThId, NULL, lpStartAddress, lpParameter);
	return (rc==0) ? *pThId : INVALID_THREAD_VALUE;
}

BOOL IsThreadAlive (THREAD_ID ThId)
{
	void *rc;
	if ( pthread_tryjoin_np (ThId, &rc) == 0 )
	{ 
		pthread_join (ThId, &rc) ;
		return FALSE;
	}
	return TRUE;
}

int GetExitCodeThread (THREAD_ID ThId, DWORD *rez) { *rez=0 ; return 0; }
int CloseHandle (THREAD_ID ThId)             { return 0; }

#endif
// ---------------------------------------------------------
// end of tweaks 
// ---------------------------------------------------------


// default parameters
#define DEFAULT_BURST_PKTS    2
#define DEFAULT_BUFLEN       (1448*DEFAULT_BURST_PKTS)    // buffer size for reading HTTP command and file content (2 pkts of 1500 bytes)
char DEFAULT_PORT[] =  "8080"    ;
#define DEFAULT_MAXTHREADS   1024             // maximum simultaneous connections
char DEFAULT_HTMLFILE[] = "index.html"; // if request is "GET / HTTP/1.1"

// params passed to logger funcion
enum { LOG_BEGIN, LOG_END, };		// 

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

struct S_ErrorCodes
{
	int	    status_code;
	const char *txt_content;
	const char *html_content;
}
sErrorCodes[] = 
{	
	{ HTTP_BADREQUEST,	      "Bad Request",            "HTTP malformed request syntax.",  },
    { HTTP_NOTFOUND,	      "Not Found",              "The requested URL was not found on this server.",  },
    { HTTP_SECURITYVIOLATION, "Forbidden",              "Directory traversal attack detected.",             },
    { HTTP_TYPENOTSUPPORTED,  "Unsupported Media Type", "The requested file type is not allowed on this simple static file webserver.", },
    { HTTP_METHODNOTALLOWED,  "Method Not Allowed",     "The requested file operation is not allowed on this simple static file webserver.", },
    { HTTP_SERVERERROR,       "Internal Server Error",  "Internal Server Error, can not access to file anymore.", },
};

const char szHTMLErrFmt[]  = "<html><head>\n<title>%d %s</title>\n</head><body>\n<h1>%s</h1>\n%s\n</body></html>\n";
const char szHTTPDataFmt[] = "HTTP/1.1 %d %s\nServer: mweb-%s\nContent-Length: %I64d\nConnection: close\nContent-Type: %s\n\n";

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
		MWEB_VERSION,
		(DWORD64) strlen (szContentBuf),
		"text/html" );
	iResult = send (skt, szHTTPHeaders, strlen (szHTTPHeaders), 0);
	iResult = send (skt, szContentBuf,  strlen (szContentBuf),  0);
	return iResult;
} // HTTPSendError 

  // ---------------------------------------------------------
  // Operationnal states : settings, HTML types  and thread data
  // ---------------------------------------------------------
  // Global Settings 
struct S_Settings
{
	BOOL  bVerbose;
	BOOL  bIPv4;
	BOOL  bIPv6;
	char  *szPort;
	char  *szBoundTo;
	char  *szDefaultHtmlFile;
	char  *szDefaultContentType;	// all files accepted with this content-type
	int    max_threads;				// maximum simultaneous connections
	BOOL   slow_down;               // add a 1 second pause after each frame
}
sSettings = { FALSE, FALSE, FALSE, DEFAULT_PORT, NULL,  DEFAULT_HTMLFILE, NULL, DEFAULT_MAXTHREADS, FALSE };


// The structure for each transfer
struct S_ThreadData
{
	SOCKET      skt;			// the transfer skt
	SOCKADDR_STORAGE sa;			// keep track of the client
	char       *buf;			// buffer for communication allocated in main thread
	unsigned    buflen;			// sizeof this buffer
	char        url_filename[MAX_PATH];	// URL to be retrieved
	char        long_filename[MAX_PATH];	// canonical file name with path
	char       *file_name;			// pointer inside long_filename
	char       *file_type;			// pointer inside long_filename
	FILE       *hFile;			// file handle
	DWORD64     qwFileCurrentPos;		// pos in file (also the number of bytes sent to the client)
	DWORD64     qwFileSize;			// total size of the file
	time_t      tStartTrf;			// when the transfer has started

	THREAD_ID   ThreadId;		        // thread data (posix) or Id (Windows)
	BOOL        bThreadUp;                  // is thread running ?

											// link
	struct S_ThreadData *next;
	struct S_ThreadData *prev;
}
*pThreadDataHead;			// array allocated in main

int nbThreads = 0;                      // # running threads


										// known extensions for HTML content-type resolution
										// from https://developer.mozilla.org/nl/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Complete_list_of_MIME_types
										// automatially generated from this url with the excel formula : 
										// IF(C2="";CONCAT(" { """;A2;"""";", """;C1;""" }, ");CONCAT(" { """;A2;"""";", """;C2;""" }, "))
struct {
	const char *ext;
	const char *filetype;
} sHtmlTypes[] = {
	{ ".aac", "audio/aac" },
	{ ".abw", "application/x-abiword" },
	{ ".arc", "application/octet-stream" },
	{ ".avi", "video/x-msvideo" },
	{ ".azw", "application/vnd.amazon.ebook" },
	{ ".bin", "application/octet-stream" },
	{ ".bz", "application/x-bzip" },
	{ ".bz2", "application/x-bzip2" },
	{ ".csh", "application/x-csh" },
	{ ".css", "text/css" },
	{ ".csv", "text/csv" },
	{ ".doc", "application/msword" },
	{ ".eot", "application/vnd.ms-fontobject" },
	{ ".epub", "application/epub+zip" },
	{ ".gif", "image/gif" },
	{ ".htm", "text/html" },
	{ ".html", "text/html" },
	{ ".ico", "image/x-icon" },
	{ ".ics", "text/calendar" },
	{ ".jar",  "application/java-archive" },
	{ ".jpeg", "image/jpeg" },
	{ ".jpg",  "image/jpeg" },
	{ ".js",   "application/javascript" },
	{ ".json", "application/json" },
	{ ".mid", "audio/midi" },
	{ ".mid", "audio/midi" },
	{ ".mpeg", "video/mpeg" },
	{ ".mpkg", "application/vnd.apple.installer+xml" },
	{ ".odp", "application/vnd.oasis.opendocument.presentation" },
	{ ".ods", "application/vnd.oasis.opendocument.spreadsheet" },
	{ ".odt", "application/vnd.oasis.opendocument.text" },
	{ ".oga", "audio/ogg" },
	{ ".ogv", "video/ogg" },
	{ ".ogx", "application/ogg" },
	{ ".otf", "font/otf" },
	{ ".png", "image/png" },
	{ ".pdf", "application/pdf" },
	{ ".ppt", "application/vnd.ms-powerpoint" },
	{ ".rar", "application/x-rar-compressed" },
	{ ".rtf", "application/rtf" },
	{ ".sh", "application/x-sh" },
	{ ".svg", "image/svg+xml" },
	{ ".swf", "application/x-shockwave-flash" },
	{ ".tar", "application/x-tar" },
	{ ".tif", "image/tiff" },
	{ ".tiff", "image/tiff" },
	{ ".ts", "application/typescript" },
	{ ".ttf", "font/ttf" },
	{ ".vsd", "application/vnd.visio" },
	{ ".wav", "audio/x-wav" },
	{ ".weba", "audio/webm" },
	{ ".webm", "video/webm" },
	{ ".webp", "image/webp" },
	{ ".woff", "font/woff" },
	{ ".woff2", "font/woff2" },
	{ ".xhtml", "application/xhtml+xml" },
	{ ".xls", "application/vnd.ms-excel" },
	{ ".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
	{ ".xml", "application/xml" },
	{ ".xul", "application/vnd.mozilla.xul+xml" },
	{ ".zip", "application/zip" },
	{ ".3gp", "video/3gpp" },
	{ ".3g2", "video/3gpp2" },
	{ ".7z", "application/x-7z-compressed" },

// add-ons
{ ".mp4",  "video/mpeg" }, 
{ ".mpg",  "video/mpeg" }, 
{ ".iso",  "application/iso" }, 
{ ".txt",  "application/text" }, 
{ ".text",  "application/text" }, 
};




/////////////////////////////////////////////////////////////////
// utilities functions :
//      - report error
/////////////////////////////////////////////////////////////////


// Function LastErrorText : THREAD UNSAFE
// A wrapper for FormatMessage : retrieve the message text for a system-defined error
char *LastErrorText(void)
{
	static char szLastErrorText[512];
	// strerror_r (errno, szLastErrorText, sizeof szLastErrorText);
	strerror_s (szLastErrorText, sizeof szLastErrorText);
	return szLastErrorText;
} // LastErrorText



  // report an error to console using puts
void SVC_ERROR(const char *szFmt, ...)
{
	va_list args;
	if (sSettings.bVerbose)
	{
		va_start(args, szFmt);
		vfprintf(stderr, szFmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}
} // SVC_ERROR


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
		SVC_ERROR("Error : WSAStartup failed\nError %d (%s)", GetLastError(), LastErrorText());
		exit(-1);    // no recovery
	}
	return iResult;
} // InitSocket

int IsTransferCancelledByPeer(SOCKET skt)
{
	struct timeval to = { 0, 0 };
	fd_set fdset;
	char   recv_buf[4];
	int   iResult;
	// check if socket has been closed by client
	FD_ZERO(&fdset);
	FD_SET(skt, &fdset);
	iResult = select(0, &fdset, NULL, NULL, &to)>0
		&& recv(skt, recv_buf, sizeof recv_buf, 0) == 0;
	return iResult;
} // IsTransferCancelledByPeer


  // return the max segment size for this socket
int GetSocketMSS(SOCKET skt)
{
	int tcp_mss = 0;
	int opt_len = sizeof tcp_mss;
	int iResult;

	iResult = getsockopt(skt, IPPROTO_TCP, TCP_MAXSEG, (char*) & tcp_mss , & opt_len);
	if (iResult < 0)
	{
		SVC_ERROR("Failed to get TCP_MAXSEG for master socket.\nError %d (%s)", GetLastError(), LastErrorText());
		return -1;
	}
	return tcp_mss;
} // GetSocketMSS


  // return TRUE IPv6 is enabled on the local system
BOOL IsIPv6Enabled(void)
{
	SOCKET s = INVALID_SOCKET;
	int Rc = 0;
	// just try to open an IPv6 socket
	s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	Rc = GetLastError();  // should be WSAEAFNOSUUPORT 10047
	closesocket(s);
	return s != INVALID_SOCKET;
} // IsIPv6Enabled

  // debug
int dump_addrinfo(ADDRINFO *runp)
{
	char hostbuf[50], portbuf[10];
	int e;

	printf("family: %d, socktype: %d, protocol: %d, ", runp->ai_family, runp->ai_socktype, runp->ai_protocol);
	e = getnameinfo(
		runp->ai_addr, runp->ai_addrlen,
		hostbuf, sizeof(hostbuf),
		portbuf, sizeof(portbuf),
		NI_NUMERICHOST | NI_NUMERICSERV
	);
	printf("host: %s, port: %s\n", hostbuf, portbuf);
return 0;
}


// create a listening socket
// and bind it to the HTTP port
SOCKET BindServiceSocket(const char *port, const char *sz_bind_addr)
{
	SOCKET             sListenSocket = INVALID_SOCKET;
	int                Rc;
	ADDRINFO           Hints, *res, *cur;

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
		SVC_ERROR("Error : specified address %s is not recognized\nError %d (%s)", sz_bind_addr, GetLastError(), LastErrorText());
		return INVALID_SOCKET;
	}

	// if getaddr_info returns only one entry: take it (option -i, -4, -6 or ipv4 only host)
	// else search for  the ipv6 socket (then deactivate the option IPV6_V6ONLY)
	if (res->ai_next == NULL)     cur = res;
	else                          for (cur = res ; cur!=NULL  &&  cur->ai_family!=AF_INET6 ; cur = cur->ai_next);
	assert (cur!=NULL);

	if (sSettings.bVerbose) dump_addrinfo (cur);

	// now open socket based on either selection
	sListenSocket = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
	if (sListenSocket == INVALID_SOCKET)
	{
		SVC_ERROR("Error : Can't create socket\nError %d (%s)", GetLastError(), LastErrorText());
		return INVALID_SOCKET;
	}

	// now allow both IPv6 and IPv4 by disabling IPV6_ONLY (necessary since Vista)
	// http://msdn.microsoft.com/en-us/library/windows/desktop/bb513665(v=vs.85).aspx
	// does not work under XP --> do not check return code
	if (res->ai_next != NULL)  // did we select the ipv6 entry ?
	{
		int Param = FALSE;
		Rc = setsockopt(sListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)& Param, sizeof Param);
		printf ("setock opt %d, errno %d\n", Rc, errno);
		perror("");
	}

	// bind the socket to the active interface
	Rc = bind(sListenSocket, cur->ai_addr, cur->ai_addrlen);
	if (Rc == INVALID_SOCKET)
	{
		SVC_ERROR("Error : Can't not bind socket\nError %d (%s)", GetLastError(), LastErrorText());
		closesocket(sListenSocket);
		return INVALID_SOCKET;
	}
	// create the listen queue
	Rc = listen(sListenSocket, 5);
	if (Rc == -1)
	{
		SVC_ERROR("Error : on listen\nError %d (%s)", GetLastError(), LastErrorText());
		closesocket(sListenSocket);
		return INVALID_SOCKET;
	}

	freeaddrinfo(res);
	return   Rc == INVALID_SOCKET ? Rc : sListenSocket;
} // BindServiceSocket




  /////////////////////////////////////////////////////////////////
  // Thread management
  /////////////////////////////////////////////////////////////////

  // Do Some cleanup on terminated Threads (use pThreadDataHead as global)
int ManageTerminatedThreads (void)
{
	int ark=0;
	DWORD  iResult;
	struct S_ThreadData *pCur, *pNext;

	// check if threads have ended and free resources
	for (pCur=pThreadDataHead ;  pCur!=NULL ; pCur=pNext )
	{
		pNext = pCur->next;   // pCur may be freed
		if (pCur->bThreadUp &&  ! IsThreadAlive (pCur->ThreadId))
		{
			pCur->bThreadUp = FALSE;
			if (pCur->buf!=NULL)    free (pCur->buf);
			if (pCur->hFile!=NULL)  fclose (pCur->hFile);

			GetExitCodeThread (pCur->ThreadId, &iResult);
			CloseHandle (pCur->ThreadId);
			ark++;

			// detach pCur
			if (pCur->next!=NULL)  pCur->next->prev = pCur->prev;
			if (pCur->prev!=NULL)  pCur->prev->next = pCur->next;
			else                   pThreadDataHead  = pCur->next;
			// free record 
			printf("freeing thread %p\n", pCur);
			free (pCur);

			--nbThreads;
		}
	}
	return ark;
} // ManageTerminatedThreads


  /////////////////////////////////////////////////////////////////
  // HTTP protocol management
  //      - decode incoming message
  //      - read file and send it through the Http channel
  // resources are freed by calling thread
  /////////////////////////////////////////////////////////////////

  // a minimal reporting
int LogTransfer(const struct S_ThreadData *pData, int when, int http_status)
{
	char szAddr[INET6_ADDRSTRLEN], szServ[NI_MAXSERV];
	char szBuf[256];
	int Rc;

	if (!sSettings.bVerbose)  return 0;

	strcpy (szAddr, "");
	strcpy (szServ, "");
	Rc = getnameinfo((LPSOCKADDR)& pData->sa, sizeof pData->sa,
		szAddr, sizeof szAddr,
		szServ, sizeof szServ,
		NI_NUMERICHOST | NI_NUMERICSERV);
	if (Rc!=0) 
	{
		errno = Rc;
		SVC_ERROR("gtenameinfo failed.\nError %d (%s)", Rc, LastErrorText());
	}
	// do not use ipv4 mapped address
	if (* (unsigned short *) szAddr == * (unsigned short *) "::")
		memmove (szAddr, & szAddr[sizeof "::ffff:" - 1], sizeof "255.255.255.255");

	switch (when)
	{
	case LOG_BEGIN:
		StringCchPrintf(szBuf, sizeof szBuf, "From %s:%s, GET %s. burst size %d", 
			szAddr, szServ, pData->file_name, pData->buflen);
		break;

	case LOG_END:
		StringCchPrintf(szBuf, sizeof szBuf, "From %s:%s, GET %s: %I64d bytes sent, status : %d",
			szAddr, szServ, pData->file_name,
			pData->qwFileCurrentPos, http_status );
		break;
	}
	return	puts(szBuf);
} // LogTransfer



  // translate file extension into HTTP content-type field
  // Get extension type 
char *GetHtmlContentType(const char *os_extension)
{
	int ark;

	if (os_extension == NULL)  
		return  sSettings.szDefaultContentType;

	// search for extension (do case insentive matching even for unix)
	for (ark = 0; ark<sizeof(sHtmlTypes) / sizeof(sHtmlTypes[0]); ark++)
		if (strcasecmp (sHtmlTypes[ark].ext, os_extension) == 0) break;
	if (ark >= sizeof(sHtmlTypes) / sizeof(sHtmlTypes[0]))
	{
		SVC_ERROR("Unregistered file extension");
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


	// set beginning of filename, then find its end (first space)
	// file name is supposed to start with '/', anyway accepts if / is missing
	pCur = szHttpRequest[4] == '/' ? &szHttpRequest[5] : &szHttpRequest[4];
	pEnd = strpbrk(pCur, "\r\n ?");
	if (*pEnd != ' ' && *pEnd != '?')		// if anormal endings
	{
		return FALSE;
	}
	// now we ignore all the other stuff sent by client....
	// just copy the file name
	url_length = pEnd - pCur;
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

	// ensure request is a GET
	CharUpperBuff(pData->buf, sizeof "GET " - 1);
	if (memcmp(pData->buf, "GET ", sizeof "GET " - 1) != 0)
	{
		SVC_ERROR("Only Simple GET operations supported");
		return HTTP_METHODNOTALLOWED;
	}
	// extract file name
	if (!ExtractFileName(pData->buf, request_length, pData->url_filename, sizeof pData->url_filename))
	{
		SVC_ERROR("invalid HTTP formatting");
		return HTTP_BADREQUEST;
	}
	// get canonical name && locate the file name location
	// Valid since we are in the main thread
	GetFullPathName(pData->url_filename, MAX_PATH, pData->long_filename, &pData->file_name);
	if (pData->file_name == NULL)
		pData->file_type = NULL;
	else
		pData->file_type = strrchr(pData->file_name, '.');	// search for '.'

															// sanity check : do not go backward in the directory structure
	GetFullPathName(".", MAX_PATH, szCurDir, NULL);
#ifdef UNSAFE__DEBUG
	printf("file to be retreived is %s, path is %s, file is %s, cur dir is %s\n", pData->long_filename, pData->buf, pData->file_name, szCurDir);
#endif
	if (memcmp(szCurDir, pData->long_filename, strlen(szCurDir)) != 0)
	{
		SVC_ERROR("directory traversal detected");
		return HTTP_SECURITYVIOLATION;
	}
	return HTTP_OK;
} // DecodeHttpRequest


  // we don't expect anything from client, but it may abort the connection 



  // Thread base
THREAD_RET HttpTransferThread(void * lpParam)
{
	int      bytes_rcvd;
	DWORD    bytes_read;
	char     *pContentType;
	struct S_ThreadData *pData = (struct S_ThreadData *)  lpParam;
	int      iResult = -1;
	int      iHttpStatus=HTTP_BADREQUEST;
	int      tcp_mss;

	pData->bThreadUp = TRUE;   //�thread is started

							   // get http request
	bytes_rcvd = recv(pData->skt, pData->buf, pData->buflen - 1, 0);
	if (bytes_rcvd < 0)
	{
		SVC_ERROR("Error in recv\nError %d (%s)", GetLastError(), LastErrorText());
		goto cleanup;
	}
	// modify buffer size depending on MSS
	if ( (tcp_mss = GetSocketMSS(pData->skt)) > 0 ) 
		pData->buflen = DEFAULT_BURST_PKTS * tcp_mss;

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
	if (pData->hFile == NULL)
	{
		SVC_ERROR("Error opening file %s\nError %d (%s)", pData->long_filename, GetLastError(), LastErrorText());
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
		MWEB_VERSION,
		pData->qwFileSize,
		pContentType);
	send(pData->skt, pData->buf, strlen(pData->buf), 0);
	LogTransfer(pData, LOG_BEGIN, 0);

	iHttpStatus = HTTP_PARTIAL;
	do
	{
		bytes_read = fread (pData->buf, 1, pData->buflen, pData->hFile);
		send(pData->skt, pData->buf, bytes_read, 0);
		pData->qwFileCurrentPos += bytes_read;

		if (IsTransferCancelledByPeer(pData->skt)) 
			break;
		if (sSettings.slow_down) ssleep(1);
	} while (bytes_read>0);

	if ( bytes_read==0 && !feof(pData->hFile) )	//note: if transfer cancelled report OK anyway
	{
		SVC_ERROR("Error in ReadFile\nError %d (%s)", GetLastError(), LastErrorText());
		iHttpStatus = HTTP_SERVERERROR;
		goto cleanup;
	}
	// if we reach this point file was successfully sent
	iHttpStatus = HTTP_OK;

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
	ssleep(1);

	return (THREAD_RET) 0;  // return NULL to please compiler

} // HttpTransferThread



  /////////////////////////////////////////////////////////////////
  // main
  //      - create the listening socket
  //      - loop on waiting for incoming connection
  //        - start a new thread for each connection
  /////////////////////////////////////////////////////////////////

  // process args (mostly populate settings structure)
  // loosely processed : user can crash with invalid args...
int ParseCmdLine(int argc, char *argv[])
{
	int ark;
	for (ark = 1; ark < argc; ark++)
	{
		if (argv[ark][0] == '-')
		{
			switch (argv[ark][1])
			{
			case '4': sSettings.bIPv6 = FALSE; break;
			case '6': sSettings.bIPv4 = FALSE; break;
			case 'c': sSettings.szDefaultContentType = argv[ark + 1];  ark++;  break;
			case 'd': if (!SetCurrentDirectory(argv[++ark]))
				SVC_ERROR("can not change directory to %s\nError %d (%s)",
					argv[ark], GetLastError(), LastErrorText());
				break;
			case 'g': sSettings.slow_down = TRUE;   break;
			case 'i': sSettings.szBoundTo = argv[ark + 1];  ark++;  break;
			case 'p': sSettings.szPort = argv[++ark];  break;
			case 's': sSettings.max_threads = atoi(argv[ark + 1]); ark++; break;
			case 'v': sSettings.bVerbose = TRUE;   break;
			case 'x': sSettings.szDefaultHtmlFile = argv[ark + 1];  ark++;  break;
				break;
			default:
				puts(SYNTAX);
				exit(1);

			} // switch
		} // args prefixed by "-"
		else
		{
			puts(SYNTAX);
			exit(1);
		}
	} // for all args
	return ark;
} // ParseCmdLine


  // main loop 
void doLoop(SOCKET ListenSocket)
{
	SOCKADDR_STORAGE sa;
	int    sa_len;
	SOCKET ClientSocket;
	DWORD  iResult;
	THREAD_ID Rc;
	struct S_ThreadData *pCur;

	// Accept new client connection
	sa_len = sizeof sa;
	memset(&sa, 0, sizeof sa);
	ClientSocket = accept(ListenSocket, (struct sockaddr *) & sa, &sa_len);
	if (ClientSocket == INVALID_SOCKET) {
		SVC_ERROR("Error : Accept failed\nError %d (%s)", GetLastError(), LastErrorText());
		closesocket(ListenSocket);
		WSACleanup();
		exit(1);
	}

	// resources available ? 
	if (++nbThreads >= sSettings.max_threads)
	{
		if (sSettings.bVerbose)
			puts("ignore request : too many simultaneous transfers\n");
		ssleep (3);  // let others threads terminate
	}
	else
	{

		// create a new ThreadData structure and populate it
		pCur = (struct S_ThreadData *) calloc (1, sizeof *pCur);
		if (pCur == NULL)
			SVC_ERROR("can not allocate memory");
		printf("allocatin thread %p\n", pCur);

		// put record at the head of the linked list
		pCur->next = pThreadDataHead;
		if (pThreadDataHead!=NULL)  pThreadDataHead->prev = pCur;
		pThreadDataHead = pCur;

		// populate record
		pCur->sa = sa;
		pCur->buflen = DEFAULT_BUFLEN;
		pCur->buf = (char *) malloc (pCur->buflen);
		pCur->skt = ClientSocket;
		pCur->qwFileCurrentPos = 0;
		time(& pCur->tStartTrf);

		if (pCur->buf == NULL)
			SVC_ERROR("can not allocate memory");

		// Pass the socket id to a new thread and listen again
		Rc = (THREAD_ID) _beginthreadex (NULL, 0, HttpTransferThread, pCur, 0, NULL);
		if (Rc == INVALID_THREAD_VALUE)
			SVC_ERROR("can not allocate thread");
#if defined WIN32 || defined WIN64
		pCur->ThreadId = Rc;


#endif
	} // slot available
} // doLoop



  // main program : read args, create listening socket and wait for incoming connections
int main(int argc, char *argv[])
{
	SOCKET ListenSocket;
	int ark;
	char sbuf[MAX_PATH];

	ParseCmdLine(argc, argv); // override default settings
							  // Prepare the socket
	InitSocket();
	ListenSocket = BindServiceSocket (sSettings.szPort, sSettings.szBoundTo);
	if (ListenSocket == INVALID_SOCKET)
		exit(1);

	GetCurrentDirectory(sizeof sbuf, sbuf);
	// if (sSettings.bVerbose)
	printf("uweb is listening on port %s, base directory is %s\n", 	sSettings.szPort, sbuf);

	for ( ark=0 ;  ark<10 ; ark++)
	{
		doLoop(ListenSocket);
		ManageTerminatedThreads (); // free terminated threads resources
	} // for (; ; )
	  // cleanup

	ssleep (5); // wait for last transfer 
	ManageTerminatedThreads (); // free terminated threads resources

	closesocket(ListenSocket);
	WSACleanup();

	return 0;
}