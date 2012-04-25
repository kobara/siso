PROG=siso
SRC=main.c siso.c target.c session.c connection.c debug.c misc.c iscsi.c scsi.c vol.c volstd.c config.c login.c
OBJS=$(patsubst %.c,%.o,$(SRC))
DEPENDS=$(patsubst %.c,%.d,$(SRC))

CC	= gcc
RM      = rm
CFLAGS  = -g -Wall
#CFLAGS = -O -Wall

$(PROG): $(OBJS)
	$(CC) -o $@ $(OBJS) $(CFLAGS) -lpthread -lssl

.c.o:
	$(CC) -c $(CFLAGS) $<

.PHONY : clean depend
clean:
	-$(RM) $(OBJS) $(PROG) $(DEPENDS) TAGS

%.d: %.c
	@set -e; $(CC) -MM $(CPPFLAGS) $< \
		| sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@; \
		[ -s $@ ] || rm -f $@
-include $(DEPENDS)

tags:
	etags *.[ch]
