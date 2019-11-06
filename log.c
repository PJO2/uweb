// --------------------------------------------------------
// uweb : a minimal web server which compile under MacOS, Linux and Windows
// by Ph. Jounin November 2019
// 
// License: GPLv2
// 
// module: log.c
// ---------------------------------------------------------


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "log.h"

// from uweb.h
extern struct S_Settings
{
        int   uVerbose;
} sSettings;


void LOG (int verbose_level, const char *fmt, ...)
{
char buff[1024];
va_list args;

   if (sSettings.uVerbose < verbose_level) return ;
   va_start (args, fmt);
   vsnprintf (buff, sizeof buff, fmt, args);
   buff[sizeof buff - 1] = 0;
   va_end (args);
   fprintf (verbose_level<=ERROR ? stderr : stdout, buff);   
} // LOG


