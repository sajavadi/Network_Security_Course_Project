# build an executable named mydump from mydump.c

all: quantuminject.c quantumdetect.c
	gcc quantuminject.c  -lnet  -lpcap -lpcre  -o quantuminject
	gcc quantumdetect.c   -lpcap  -o quantumdetect
clean:
	$(RM) quantuminject
	$(RM) quantumdetect
