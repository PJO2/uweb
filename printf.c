
#include <stdio.h>
#include <inttypes.h>


int main ()
{
   long i = 0x1122334455667788l;

   printf ("sizeof i is %d\n", sizeof i);
   printf ("i as int    is %i\n", i);
   printf ("i as long   is %ld\n", i);
   printf ("i as 2xlong is %lld\n", i);
   printf ("i as %s  is %" PRId64 "\n", PRId64, i);
}
