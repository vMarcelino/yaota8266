all:
	make ota
	make otaota


ota:
	rm -f ota.o
	make -f Makefile.ota.mk

otaota:
	rm -f ota.o
	make -f Makefile.otaota.mk

clean:
	rm -f *.o *.a *.elf* *-0x*.bin
