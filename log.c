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
#include <time.h>
#include "log.h"

// from uweb.h
extern struct S_Settings
{
	int   uVerbose;
	int   timestamp;
} sSettings;

void ssleep(int);



static struct tm *my_localtime_r(const time_t *tim, struct tm *result)
{
static int poor_man_mutex=1;
struct tm *t;

   while (poor_man_mutex<1) ssleep(5);
   --poor_man_mutex;

   if ( (t = localtime(tim)) != NULL)  *result = *t;
   ++poor_man_mutex;

return t ? result : NULL;
}

void LOG (int verbose_level, const char *fmt, ...)
{
char date[sizeof "2020-04-06 11:08:43, "];
char buff[1024];
va_list args;
time_t now = time(NULL);
struct tm tNow = { 0 } ; // ensure it is initialized for the compiler

   if (sSettings.uVerbose < verbose_level) return ;
   va_start (args, fmt);
   vsnprintf (buff, sizeof buff, fmt, args);
   buff[sizeof buff - 1] = 0;
   va_end (args);

   if (sSettings.timestamp)
   {
       now = time(NULL);
       my_localtime_r (&now, &tNow);
       // modulus are used to prove to smart compilers that the integers will not exceed format size
       sprintf (date, "%04u-%02u-%02u %02u:%02u:%02u, ", 
                      (tNow.tm_year + 1900) % 10000, (tNow.tm_mon + 1) % 100, 
                      tNow.tm_mday % 100, tNow.tm_hour % 100, 
                      tNow.tm_min % 100, tNow.tm_sec % 100);
       fputs (date, verbose_level<=ERROR ? stderr : stdout); 
   }
   fputs (buff, verbose_level<=ERROR ? stderr : stdout);   
} // LOG


