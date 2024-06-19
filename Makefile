.PHONY: build
CC64 = x86_64-w64-mingw32-gcc

SRC = example/main.c *.c
FLAGS = -s -Os -nostdlib -fno-asynchronous-unwind-tables

OUT = -o gimmick.exe

build:
	$(CC64) $(FLAGS) $(SRC) $(OUT) -DDEBUG
	python3 crypt.py -f gimmick.exe -o gimmick.exe -s .xdata .rodata

release:
	$(CC64) $(FLAGS) $(SRC) $(OUT)
	python3 crypt.py -f gimmick.exe -o gimmick.exe -s .xdata .rodata