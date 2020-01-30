all:otaonly otaota yaota

base:
	$(MAKE) -C boot8266
	$(MAKE) -C ota-server

otaonly:base
	python merge.py -o ota.bin ota-server/ota.elf-0x00000.bin ota-server/ota.elf-0x09000.bin

otaota:
	$(MAKE) -C boot8266
	$(MAKE) -C ota-server ota
	python makeimg.py ota-server/otaota.elf-0x00000.bin ota-server/otaota.elf-0x45000.bin otaota.bin


yaota:base
	python merge.py -o yaota8266.bin boot8266/boot8266-0x00000.bin \
	    ota-server/ota.elf-0x00000.bin ota-server/ota.elf-0x09000.bin

flash:all
	python -m esptool -p /dev/ttyUSB0 --baud 230400 write_flash -fm dout --flash_size=detect 0x0 yaota8266.bin
	rm espflash.cap
	minicom -D /dev/ttyUSB0 -C local.espflash.cap

cleanflash: all
	python -m esptool -p /dev/ttyUSB0 --baud 230400 erase_flash
	python -m esptool -p /dev/ttyUSB0 --baud 230400 write_flash -fm dout --flash_size=detect 0x0 yaota8266.bin 0x3c000 ../bin/firmware-ota-Fan.bin
	rm espflash.cap
	minicom -D /dev/ttyUSB0 -C local.espflash.cap

clean:
	$(MAKE) -C boot8266 clean
	$(MAKE) -C ota-server clean
	rm -f ota.bin otaota.bin yaota8266.bin
