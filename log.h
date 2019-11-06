// --------------------------------------------------------
// uweb : a minimal web server which compile under MacOS, Linux and Windows
// by Ph. Jounin November 2019
// 
// License: GPLv2
// Module : 
//              - log.h
// ---------------------------------------------------------


// LOG levels
enum { FATAL=-1, ERROR, WARN, INFO, DEBUG, TRACE, ALL };

void LOG (int verbose_level, const char *fmt, ...);



