/*
 * This file is part of the MicroPython project, http://micropython.org/
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

#include <stdio.h>
#include "ets_sys.h"
#include "../boot8266/etshal.h"
//#include "esp_mphal.h"
#include "user_interface.h"
//#include "extmod/misc.h"

#define NORETURN __attribute__((noreturn))
NORETURN void call_user_start(void);
void ets_printf(const char *fmt, ...);
extern SpiFlashChip *flashchip;

#define esp_init_data_start flashchip->chip_size - 1024 * 16

static const uint8_t default_init_data[] __attribute__((aligned(4))) = {
    0x05, 0x00, 0x04, 0x02, 0x05, 0x05, 0x05, 0x02, 0x05, 0x00, 0x04, 0x05, 0x05, 0x04, 0x05, 0x05,
    0x04, 0xfe, 0xfd, 0xff, 0xf0, 0xf0, 0xf0, 0xe0, 0xe0, 0xe0, 0xe1, 0x0a, 0xff, 0xff, 0xf8, 0x00,
    0xf8, 0xf8, 0x52, 0x4e, 0x4a, 0x44, 0x40, 0x38, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe1, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x93, 0x43, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// void pm(uint8_t *mem)
// {

//     //print X label
//     ets_printf("         ");
//     for (int i = 1; i <= 16; i++)
//     {
//         ets_printf("%2d ", i);
//     }
//     ets_printf("\n\n ");

//     // print Y label and items
//     for (int i = 0; i < 8; i++)
//     {
//         ets_printf("%d(%3d)  ", i + 1, i * 16);
//         for (int j = 0; j < 16; j++)
//         {
//             const int l = i * 16 + j;
//             ets_printf("%02x ", mem[l]);
//         }
//         ets_printf("\n ");
//     }
// }
// void print_mem_comp(uint8_t *mem, uint8_t *mem2)
// {
//     if (mem == NULL)
//         mem = default_init_data;

//     //print X label
//     ets_printf("         ");
//     for (int i = 1; i <= 16; i++)
//     {
//         ets_printf("%2d ", i);
//     }
//     ets_printf("\n\n ");

//     // print Y label and items
//     for (int i = 0; i < 8; i++)
//     {
//         ets_printf("%d(%3d)  ", i + 1, i * 16);
//         for (int j = 0; j < 16; j++)
//         {
//             const int l = i * 16 + j;
//             if (mem2 == NULL)
//                 ets_printf("%02x ", mem[l]);

//             else
//                 ets_printf("%s  ", mem[l] == mem2[l] ? "." : "#");
//         }
//         ets_printf("\n ");
//     }
// }

// void print_mem_s(uint8_t *mem, uint32_t start)
// {
//     ets_printf("offset: %x", start);
//     SPIRead(start, mem, sizeof(mem));
//     print_mem_comp(mem, NULL);
//     ets_printf("\n\n\n");
//     print_mem_comp(NULL, mem);
//     ets_printf("\n\n\n");
// }
// void print_mem(uint8_t *mem)
// {
//     print_mem_s(mem, esp_init_data_start);
// }

void firmware_start(void)
{
    // For SDK 1.5.2, either address has shifted and not mirrored in
    // eagle.rom.addr.v6.ld, or extra initial member was added.
    //ets_printf("             test: 0x%x\n", testval);
    //ets_printf("       flash chip: 0x%x\n", flashchip);
    //SpiFlashChip *flash = (SpiFlashChip *)(flashchip);

    ets_printf("OTA firmware\n");

    ets_printf("chip size (Bytes): %u\n", flashchip->chip_size);

    // the init data must be at the last 16KB of the flash

    //char buf[128];

    bool inited = false;
    // for (int i = 0; i < sizeof(buf); i++)
    // {
    //     if (buf[i] != 0xff)
    //     {
    //         inited = true;
    //         break;
    //     }
    // }

    if (!inited)
    {
        ets_printf("Writing init data\n");
        //SPIRead((uint32_t)&default_init_data - 0x40200000, buf, sizeof(buf));
        SPIWrite(esp_init_data_start, default_init_data, sizeof(default_init_data));
        ets_printf("Done writing\n");
    }
    ets_printf("Starting app\n");

    asm("j call_user_start");
}
