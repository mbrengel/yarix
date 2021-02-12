# compiler/linker stuff
CFLAGS += -Wall -Wextra -Wpedantic -Ofast

all: tools/buildindex tools/merge pythonmodule

tools/buildindex.o: tools/buildindex.c tools/buildindex.h tools/util/primes.h tools/util/qsort.h tools/util/uthash.h
	$(CC) $(CFLAGS) -c -o $@ $<

tools/buildindex: tools/buildindex.o
	$(CC) $< -lz -pthread -o $@
	ln -sf src/tools/buildindex ../buildindex

tools/merge.o: tools/merge.c tools/util/postinglistfile.h
	$(CC) $(CFLAGS) -c -o $@ $<

tools/merge: tools/merge.o
	$(CC) $< -lz -pthread -o $@

pythonmodule:
	cd pymodule ; python3 setup.py build
	find pymodule -iname "*.so" -exec ln -sf src/{} ../malindexhelper.so \;

.PHONY: clean
clean:
	rm -rf tools/buildindex.o tools/buildindex tools/merge.o tools/merge pymodule/build ../malindexhelper.so ../buildindex
