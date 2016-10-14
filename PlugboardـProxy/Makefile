# build an executable named bpproxy from bpproxy.cpp

all: pbproxy.cpp KeyGenerator.cpp
	g++ pbproxy.cpp -lpthread -lm -lcrypto -lssl -Wno-error=deprecated-declarations   -o pbproxy
	g++ KeyGenerator.cpp -lm -lcrypto -lssl -Wno-error=deprecated-declarations   -o KeyGenerator
clean:
	$(RM) pbproxy
	$(RM) KeyGenerator
