#include <stdio.h>
#include <ctype.h>

#include "debug.h"


void print_hex(char *buf, int len)
{
        int i,l;
        unsigned char c;

        if (len <=0 || len > 0xFFFF) {
                return;
        }

        /* print header line */
        // line number
        printf("     ");
        // hex dump
        for (i = 0; i < 16; i++) {
                printf( "  %X", i);
        }
        // ascii dump
        printf(" | ");
        for (i = 0; i < 16; i++) {
                printf( "%X", i);
        }
        printf("\n");

        // print data line
        for (l = 0; l < (len-1)/16+1; l++) {
                // line number
                printf("%04X ", l*16);
                // hex dump
                for (i = 0; i < 16 && l*16+i < len; i++) {
                        c = ((unsigned char *)buf)[l*16 + i];
                        printf(" %02X", c);
                }
                for (; i < 16; i++) {
                        printf("   ");
                }
                // ascii dump
                printf(" | ");
                for (i = 0; i < 16 && l*16+i < len; i++) {
                        c = ((unsigned char *)buf)[l*16 + i];
                        if (isgraph(c)) {
                                printf("%c", c);
                        } else {
                                printf(" ");
                        }
                }
                printf("\n");
        }

        return;
} // print_hex
