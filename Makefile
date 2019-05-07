CXX ?= g++
CXXFLAGS = -g -O0
CPPFLAGS = -I/usr/include/botan-2
LDLIBS = -lbotan-2

myprograms += tls_client
myprograms += dtls_client

.PHONY: all
all: $(myprograms)

.PHONY: clean
clean:
	$(RM) $(myprograms)
