
ifneq (,$(wildcard $(NRFJPROG_PATH)/nrfjprogdll.h))
    NRFJPROG_REAL_PATH=$(NRFJPROG_PATH)
else ifneq (,$(wildcard $(NRFJPROG_PATH)/nrfjprog/nrfjprogdll.h))
    NRFJPROG_REAL_PATH=$(NRFJPROG_PATH)/nrfjprog
else
    NRFJPROG_EXE_PATH=$(shell which nrfjprog)
    ifneq (,$(NRFJPROG_EXE_PATH))
        NRFJPROG_REAL_PATH=$(dir $(NRFJPROG_EXE_PATH))
    endif
endif

NRFJPROG_REAL_PATH := $(NRFJPROG_REAL_PATH:/=)
NRFJPROG_REAL_PATH := $(NRFJPROG_REAL_PATH:/=)

ifeq (,$(NRFJPROG_REAL_PATH))
    $(info Directory containing nrfjprog must be in your PATH variable or)
    $(info NRFJPROG_PATH pointing that directory must be provided.)
    $(error Cannot find nrfjprog directory.)
endif

all: slip2

clean:
	rm -f slip2

slip2: main.c tap.c slip.c options.c
	gcc -g -O0 -o $@ -pthread -I$(NRFJPROG_REAL_PATH) -L$(NRFJPROG_REAL_PATH) $^ -lnrfjprogdll -ldl

