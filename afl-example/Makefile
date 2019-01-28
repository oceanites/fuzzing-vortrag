clean:
	rm -f a.out
	rm -rf ./fuzzing-results/*
compile:
	afl-gcc -static programm.c
fuzz:
	# disable on check for the right cpu gouvernour setting
	# will decrease performance, but this is just an example
	AFL_SKIP_CPUFREQ=1 afl-fuzz -i ./testkorpus/ -o ./fuzzing-results/ -- ./a.out
all: clean compile fuzz

.Phony: clean all
