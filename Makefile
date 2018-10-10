
all: slip2

clean:
	rm -f slip2

slip2: main.c tap.c slip.c options.c
	gcc -g -O0 -o slip2 -pthread -I/dk/apps/nrf-tools/nrfjprog -L/dk/apps/nrf-tools/nrfjprog $^ -lnrfjprogdll -ljlinkarm_nrf52_nrfjprogdll -ldl
