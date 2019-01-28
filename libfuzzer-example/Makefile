clean:
	rm -f crash-*
compile:
	clang++ -fsanitize=address,fuzzer -fsanitize-coverage=trace-pc-guard programm.cc
fuzz:
	./a.out
all: clean compile fuzz

.Phony: clean all
