CXX ?= g++
CXXFLAGS = -g -O0
CPPFLAGS = -I/usr/include/botan-2
LDLIBS = -lbotan-2

myprograms += tls_client
myprograms += dtls_client

.PHONY: all
all: prepare_test_env
all: $(myprograms)

mydirs += ca-certificates
mydirs += client-certificates client-private-keys
MKDIR = mkdir -p

.PHONY: create_dirs
create_dirs:
	$(MKDIR) $(mydirs)

.PHONY: prepare_test_env
prepare_test_env: create_dirs prepare_root_ca_cert prepare_client_key prepare_client_cert

.PHONY: prepare_root_ca_cert prepare_client_cert prepare_client_key

prepare_root_ca_cert: create_dirs
	$(MAKE) -C server root-ca.pem
	cp server/root-ca.pem ./ca-certificates

prepare_client_key: create_dirs
	$(MAKE) -C server client-key.pem
	cp server/client-key.pem ./client-private-keys

prepare_client_cert: create_dirs
	$(MAKE) -C server client-cert.pem
	cp server/client-cert.pem ./client-certificates

.PHONY: clean
clean:
	$(RM) $(myprograms)
