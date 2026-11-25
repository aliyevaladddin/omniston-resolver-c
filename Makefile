# Build:  make            (needs libnghttp2 + OpenSSL 1.1.1+/3.x)
#   Debian/Ubuntu: apt install libnghttp2-dev libssl-dev
#   macOS (brew):  make CFLAGS="-O2 -Wall -Wextra -I$(brew --prefix nghttp2)/include -I$(brew --prefix openssl)/include" \
#                       LDFLAGS="-L$(brew --prefix nghttp2)/lib -L$(brew --prefix openssl)/lib"
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
LDFLAGS ?=
LIBS = -lnghttp2 -lssl -lcrypto

.PHONY: all clean

all: resolver

resolver: omniston_resolver.c escrow.c solver_adapter.c pb.h pbtypes.h escrow.h solver.h
	$(CC) $(CFLAGS) omniston_resolver.c escrow.c solver_adapter.c -o $@ $(LDFLAGS) $(LIBS)

demo: omniston_resolver.c escrow.c solver_demo.c pb.h pbtypes.h escrow.h solver.h
	$(CC) $(CFLAGS) omniston_resolver.c escrow.c solver_demo.c -o resolver_demo $(LDFLAGS) $(LIBS)

clean:
	rm -f resolver resolver_demo *.o
