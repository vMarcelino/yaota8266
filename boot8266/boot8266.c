/*
 * This file is part of the yaota8266 project.
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Paul Sokolovsky
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <string.h>

#include "ets_sys.h"
#include "user_interface.h"
#include "gpio.h"
#include "uart_register.h"
#include "etshal.h"
#include "../config.h"

uint32_t SPIRead(uint32_t offset, void *buf, uint32_t len);
uint32_t SPIWrite(uint32_t offset, const void *buf, uint32_t len);
void _printf(const char *, ...);

#define CPU_TICKS_PER_MS 80000
#define UART0 0
#define RTCMEM_BASE 0x60001000
#define RTCMEM_SYSTEM (RTCMEM_BASE + 0x100)
// "reset info" prepared by vendor SDK is at the start of RTC memory
// ref: 0x402525a7 (main_sdk_init2+0x11f)
#define rtc_rst_info ((struct rst_info *)RTCMEM_SYSTEM)

#define CONFIG_PARAM __attribute__((section(".param")))

CONFIG_PARAM uint32_t gpio_mask = GPIO_MASK;
CONFIG_PARAM uint32_t gpio_wait_ms = GPIO_WAIT_MS;

__attribute__((always_inline)) static inline uint32_t ticks_cpu(void)
{
    uint32_t ccount;
    __asm__ __volatile__("rsr %0,ccount"
                         : "=a"(ccount));
    return ccount;
}

struct flash_header
{
    uint8_t sig; // 
    uint8_t num; // 
    uint8_t par1; // flash mode
    uint8_t par2; // flash size
    uint32_t start;
};

struct sect_header
{
    void *addr;
    uint32_t size;
};

// Return true if OTA should start
bool check_buttons(void)
{
    // If gpio_mask is empty, enter OTA unconditionally.
    if (!gpio_mask)
    {
        return true;
    }

    gpio_init();

    PIN_FUNC_SELECT(PERIPHS_IO_MUX_GPIO0_U, FUNC_GPIO0);
    PIN_PULLUP_DIS(PERIPHS_IO_MUX_GPIO0_U);

    uint32_t gpio_ini = gpio_input_get();
    _printf("Initial GPIO state: %x, OE: %x\n", gpio_ini, *(uint32_t *)0x60000314);
    gpio_ini &= gpio_mask;

    //// check magic word
    long length = *((long *)(RTCMEM_BASE + 512 + 16));
    // debug: _printf("Length: %d\n",length);

    // reading of local strings seems not to work
    // (maybe due to alignment and memory model)
    // so just check hex
    // yaotaota is in hex: 79616f74 616f7461
    // due to byte order, we need to use 746f6179 61746f61

    long *userrtc = (long *)(RTCMEM_BASE + 512 + 20);

    if (length >= 8)
    {
        _printf("RTC user memory: %x %x\n", userrtc[0], userrtc[1]);
        _printf("     Comparator: %x %x\n", 0x746f6179, 0x61746f61);
        if (userrtc[0] == 0x746f6179 && userrtc[1] == 0x61746f61)
        {
            _printf("Detected magic word in RTC memory, going to OTA mode.\n");
            *((long *)userrtc) = 0x746f617a; // change to zota, so it's not executed again
                                             // but allows trace later
            return true;
        }
        _printf("Magic word in RTC memory not detected, continuing normally.\n");
    }

    //// check GPIO
    bool ota = false;
    int ms_delay = gpio_wait_ms;
    uint32_t ticks = ticks_cpu();
    while (ms_delay)
    {
        uint32_t gpio_last = gpio_input_get() & gpio_mask;
        if (gpio_last != gpio_ini)
        {
            _printf("GPIO changed: %x\n", gpio_last);
            ota = true;
            break;
        }
        if (ticks_cpu() - ticks > CPU_TICKS_PER_MS)
        {
            ms_delay--;
            ticks += CPU_TICKS_PER_MS;
        }
        //system_soft_wdt_feed();
    }

    return ota;
}

extern char _bss_end;

bool check_main_app(void)
{
    //_printf("check_main_app\n");
    MD5_CTX ctx;
    MD5Init(&ctx);

    uint32_t read_offset = MAIN_APP_OFFSET;
    uint32_t sz = 0; // size in bytes of flash + rom (in this case flash is always 0x9000)

    // read last 4 bytes (32bits) of
    // 36864 bytes (36kB) ahead from 
    // the app space into sz variable
    SPIRead(MAIN_APP_OFFSET + (0x9000 - 4), &sz, sizeof(sz));
    if (sz > 800000)
    {
        _printf("Invalid main app size: %u\n", sz); // why??
        return false;
    }

    // now update MD5 by chunks
    while (sz != 0)
    {
        int chunk_sz = sz > 4096 ? 4096 : sz; // chunk_sz=clamp(sz, max=4096)

        // read into _bss_end the chunk
        SPIRead(read_offset, &_bss_end, chunk_sz);

        // updates the MD5 hash
        if (read_offset == MAIN_APP_OFFSET)
        {
            // MicroPython's makeimg.py skips first 4 bytes
            MD5Update(&ctx, &_bss_end + 4, chunk_sz - 4);
        }
        else
        {
            MD5Update(&ctx, &_bss_end, chunk_sz);
        }

        // moves chunk forward
        sz -= chunk_sz;
        read_offset += chunk_sz;
    }

    // read_offset is now at the end of the app

    unsigned char saved_digest[16];
    SPIRead(read_offset, saved_digest, sizeof(saved_digest));
    
    // save MD5 into calculated_digest
    unsigned char calculated_digest[16];
    MD5Final(calculated_digest, &ctx);

    return memcmp(saved_digest, calculated_digest, sizeof(saved_digest)) == 0; // return true if digests are equal
}

void uart_flush(uint8 uart)
{
    while (true)
    {
        uint32 fifo_cnt = READ_PERI_REG(UART_STATUS(uart)) & (UART_TXFIFO_CNT << UART_TXFIFO_CNT_S);
        if ((fifo_cnt >> UART_TXFIFO_CNT_S & UART_TXFIFO_CNT) == 0)
        {
            break;
        }
    }
}

void start()
{
    uint32_t boot_location = MAIN_APP_OFFSET;

    // If it's wake from deepsleep, boot main app ASAP
    if (rtc_rst_info->reason == REASON_DEEP_SLEEP_AWAKE)
    {
        goto boot;
    }

#if BAUD_RATE
    uart_flush(UART0);
    // At this point, hardware doesn't yet know that it runs with 26MHz
    // crystal oscillator instead of "default" 40MHz, so adjust baud rate
    // accordingly.
    uart_div_modify(UART0, UART_CLK_FREQ / (BAUD_RATE * 40 / 26));
#endif

    memset((void *)0x3ffe8000, 0, 0x3fffc000 - 0x3ffe8000);

    _printf("\n\nboot8266\n");

    _printf("HW RTC Reset reason: %d\n", rtc_get_reset_reason());
    _printf("System reset reason: %d\n", rtc_rst_info->reason);

    bool ota = check_buttons();

    if (!ota)
    {
        if (!check_main_app())
        {
            ota = true;
        }
    }

    if (ota)
    {
        _printf("Running OTA\n");
        boot_location = 0x1000; // is it always here?? is boot8266 always 4096 bytes? yep
    }
    else
    {
        _printf("Running app\n");
    }

    union {
        struct flash_header flash;
        struct sect_header sect;
    } header;

boot:
    SPIRead(boot_location, &header.flash, sizeof(header.flash));
    boot_location += sizeof(header.flash);

    register uint32_t start = header.flash.start;
    int num = header.flash.num;

    register uint32_t iram_offset = 0;
    register void *iram_addr = NULL;
    register uint32_t iram_size = 0;

    // Any _printf() beyond this point may (will) corrupt memory
    while (num--)
    {
        SPIRead(boot_location, &header.sect, sizeof(header.sect));
        boot_location += sizeof(header.sect);
        //_printf("read_offset: %x addr: %x size: %x\n", offset, header.sect.addr, header.sect.size);
        if ((void *)0x40100000 <= header.sect.addr && header.sect.addr < (void *)0x40108000)
        {
            //_printf("skip iram\n");
            iram_offset = boot_location;
            iram_addr = header.sect.addr;
            iram_size = header.sect.size;
        }
        else
        {
            //_printf("load\n");
            SPIRead(boot_location, header.sect.addr, header.sect.size);
        }
        boot_location += header.sect.size;
    }

    //_printf("iram: %x %p %x s: %x\n", iram_offset, iram_addr, iram_size, start);

    asm volatile("mov a5, %0"
                 :
                 : "r"(SPIRead));
    asm volatile("mov a0, %0"
                 :
                 : "r"(start));
    asm volatile("mov a3, %0"
                 :
                 : "r"(iram_addr));
    asm volatile("mov a4, %0"
                 :
                 : "r"(iram_size));
    asm volatile("mov a1, %0"
                 :
                 : "r"(0x40000000));
    asm volatile("mov a2, %0"
                 :
                 : "r"(iram_offset));
    asm volatile("jx a5\n");
}
