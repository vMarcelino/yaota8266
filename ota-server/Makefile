all:
	make default
	make ota


default:
	rm -f *.o
	make -f Makefile.default

ota:
	rm -f *.o
	make -f Makefile.ota

clean:
	rm -f *.o *.a *.elf* *-0x*.bin
