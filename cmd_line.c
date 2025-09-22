// --------------------------------------------------------
// uweb : a minimal web server which compile under MacOS, Linux and Windows
// by Ph. Jounin November 2019 - 2025
// 
// License: GPLv2
// Sources : 
//              - nweb23.c from IBM and Nigel Griffiths
//              - mweb.cpp from Ph. Jounin
// ---------------------------------------------------------


// Changes:
// from 1.3
//  - add reuse port and reuse address socket option
//  - add HEAD request processing
//  - display the incoming request with the -vv option
//  - change buffer size to 5 x MSS
// from 1.4
// - display time spent after a tranfer
// from 1.5
// - file not found: earlier detection
// - add mentions of -ct and -cb in unspported media type report
// - header Server change from mweb to uweb
// - add option -V to display version
// from 1.6
// - encapsulate all terminal outputs into function log
// - change default log level to WARN (and add -quiet option)
// - data and structures sent to h files
// - Windows release compiled with Pelles C
// - set hFile pointer to INVALID_FILE_VALUE after dry run opening
// from 1.7
// - add timestamp into log (option -t)
// - improve handling of -c (-cn did not trigger an error, instead it skipped next param)
// - display MSS in debug mode
// - change display for headers/request in debug mode
// from 1.8
// add a check after strpbrk that EoL has been found


const char SYNTAX[] = ""
"uweb: Usage\n"
"\n uweb   [-4|-6] [-p port] [-d dir] [-i addr] [-c content-type|-ct|-cb]"
"\n        [-g msec] [-s max connections] [-verbose] [-quiet] [-x file]\n"
"\n      -4   IPv4 only"
"\n      -6   IPv6 only"
"\n      -c   content-type assigned to unknown files"
"\n           (default: reject unregistered types)"
"\n           [-ct: default text/plain], [-cb: default application/octet-stream]"
"\n      -d   base directory for content (default is current directory)"
"\n      -g   slow down transfer by waiting for x msc between two frames"
"\n      -i   listen only this address"
"\n      -p   HTTP port (defaut is 8080)"
"\n      -q   quiet (decrease log level)"
"\n      -s   maximum simultaneous connections (default is 1024)"
"\n      -v   verbose (can be used up to 5 times)"
"\n      -V   display version and exit"
"\n      -x   set the default page for a directory (default is index.html)"
"\n";

#define _CRT_SECURE_NO_WARNINGS	1
#define _CRT_SECURE_NO_DEPRECATE


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#ifdef UNIX
typedef int            BOOL;
#endif 

#include "uweb.h"
#include "log.h"

struct S_Settings sSettings = { WARN, FALSE, FALSE, FALSE, DEFAULT_PORT, NULL, ".", DEFAULT_HTMLFILE, NULL, DEFAULT_MAXTHREADS, FALSE };



// -------------------
// inits 
// -------------------

void BAD_PARAMS()
{
    sSettings.uVerbose = INFO;  // ensure message is dispayed
    LOG (INFO, SYNTAX);
    exit(1);

} // BAD_PARAMS

  // process args (mostly populate settings structure)
  // loosely processed : user can crash with invalid args...
int ParseCmdLine(int argc, char *argv[])
{
	int ark, idx;
	const char *p=NULL; 
	char type_p=' ' ; // character which determine the default type binary/text

	for (ark = 1; ark < argc; ark++)
	{
		if (argv[ark][0] == '-')
		{
			switch (argv[ark][1])
			{
			case '4': sSettings.bIPv6 = FALSE; break;
			case '6': sSettings.bIPv4 = FALSE; break;
			case 'c': if (argv[ark][2]!=0)         type_p = argv[ark][2];
                                  else  if (argv[ark+1]!=NULL) type_p = argv[++ark][0];
                                  switch (type_p | 0x20)
				  {
					case 'b' : p = DEFAULT_BINARY_TYPE; break;
					case 't' : p = DEFAULT_TEXT_TYPE;   break;
					default  : BAD_PARAMS();
			          }
				  sSettings.szDefaultContentType = p;
				  break;
			case 'd': sSettings.szDirectory = argv[++ark];         break;
			case 'g': sSettings.slow_down   = atoi(argv[++ark]);   break;
			case 'i': sSettings.szBoundTo   = argv[++ark];         break;
			case 'p': sSettings.szPort      = argv[++ark];         break;
			case 'q': sSettings.uVerbose--;                        break;
			case 's': sSettings.max_threads = atoi(argv[++ark]);   break;
			case 'v': for (idx=1;  argv[ark][idx]=='v' ; idx++) 
                                       sSettings.uVerbose++;      
                                  break;
			case 't' : sSettings.timestamp = TRUE;                 break;
			case 'V': sSettings.uVerbose = INFO;
                                  LOG (INFO, "uweb version %s\n", UWEB_VERSION);
                                  exit(0);
			case 'x': sSettings.szDefaultHtmlFile = argv[++ark];   break;
				  break;
			default:  BAD_PARAMS();

			} // switch
		} // args prefixed by "-"
		else
		{
			BAD_PARAMS();
		}
	} // for all args
	return ark;
} // ParseCmdLine



  // main program : read args, create listening socket and wait for incoming connections
int main(int argc, char *argv[])
{
	ParseCmdLine(argc, argv); // override default settings

	if (! Setup ())
		exit(1);

	for (  ;  ; )
	{
		doLoop ();
	} // for (; ; )
	  // cleanup

	Cleanup();

	return 0;
}

