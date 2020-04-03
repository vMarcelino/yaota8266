all:otaonly otaota yaota
# 0x00000 - bootloader
# 0x01000 - updater
# 0x3c000 - main firmware


# builds bootloader and OTA updater to 0x3c000
base:
	$(MAKE) -C boot8266
	$(MAKE) -C ota-server ota

# makes bin with only OTA updater to 0x3c000 and copies to bin folder. Ready to be flashed at 0x01000
otaonly:base
	python merge.py -o 0x01000.ota.bin ota-server/ota.elf-0x00000.bin ota-server/ota.elf-0x09000.bin
	cp 0x01000.ota.bin ../bin/

# makes bin with the bootloader and OTA updater to 0x3c000 and copies to bin folder. Ready to be flashed at 0x0
yaota:base
	python merge.py -o 0x00000.yaota8266.bin boot8266/boot8266-0x00000.bin \
	    ota-server/ota.elf-0x00000.bin ota-server/ota.elf-0x09000.bin
	cp 0x00000.yaota8266.bin ../bin/

# makes bin with only the OTA updater to 0x01000 and copies to bin folder. Ready to be flashed at 0x3c000
otaota:
	$(MAKE) -C boot8266
	$(MAKE) -C ota-server otaota
	python makeimg.py ota-server/otaota.elf-0x00000.bin ota-server/otaota.elf-0x45000.bin 0x3c000.otaota.bin
	cp 0x3c000.otaota.bin ../bin/


flash:yaota
	python -m esptool -p /dev/ttyUSB0 --baud 230400 write_flash -fm dout --flash_size=detect 0x0 0x00000.yaota8266.bin
	rm -f local.espflash.cap
	minicom -D /dev/ttyUSB0 -C local.espflash.cap

cleanflash:yaota
	python -m esptool -p /dev/ttyUSB0 --baud 230400 erase_flash
	$(MAKE) flash

clean:
	$(MAKE) -C boot8266 clean
	$(MAKE) -C ota-server clean
	rm -f 0x01000.ota.bin 0x3c000.otaota.bin 0x00000.yaota8266.bin
