// This is user-specific config file for yaota8266 OTA bootloader.
// For compilation to succeed, this file should be copied to "config.h"
// and any settings related to RSA keys replaced with your values. Do
// not use values in this example as is - it is a security issue. You
// won't be able to perform any OTA update (because you don't have a
// private key for the public key specified here), but I will own
// your system (because I have it).

// Offset of the main application (one which will undergo OTA update)
// Default start of OTA region == size of boot8266 + ota-server, aligned
// (size of yaota8266.bin as produced by the top-level Makefile).
#ifdef OTAOTA
#define MAIN_APP_OFFSET 0x01000
#else
#define MAIN_APP_OFFSET 0x3c000
#endif

#define VERSION_MAJOR 2
#define VERSION_MINOR 0
#define VERSION_PATCH 1

// Baud rate for serial output. Set to 0 to not set baud rate explicitly,
// which them will be the default 74880.
#define BAUD_RATE 115200

// Modulus of RSA public key used to verify OTA signature
// (size is 512 bits, exponent is hardcoded at 3).
#define MODULUS "\xb8\x14\xaf\x64\x3e\x9e\x21\x89\x18\x33\xff\x98\x09\x0f\xc0\x27\x34\x29\x4b\x44\x05\x09\xdd\x64\x94\x31\xed\x76\xb3\x40\xd4\x71\x68\x3e\x4e\xbb\x18\x3d\x79\xee\x18\x00\x00\xb4\xf5\x66\x05\xee\xf0\x93\xf3\x7f\x57\xec\x92\xb4\x66\xd0\xc8\xab\xb5\x4e\x13\x23"

// How long to wait for next expected packet before assuming that
// transfer is broken and restart reception from beginning.
#define PKT_WAIT_MS 30000

// If first OTA packet isn't received during this time, reboot. This
// protects against being stuck in OTA mode if entered by accident.
#define IDLE_REBOOT_MS 60000

// Parameters below can be configured in flash too

// GPIO mask. Default value filters out UART0 and QSPI for FlashROM.
// If value is 0, then OTA is entered unconditionally. By adjusting
// IDLE_REBOOT_MS, you can make a device spend minimal time in this
// unconditional OTA mode.
#define GPIO_MASK 0xf035

// How long to wait for GPIO change to go into OTA mode.
#define GPIO_WAIT_MS 0
