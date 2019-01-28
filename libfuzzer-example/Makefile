clean:
	rm crash-*
compile:
	clang++ -fsanitize=address,fuzzer -fsanitize-coverage=trace-pc-guard programm.cc
fuzz:
	./a.out
