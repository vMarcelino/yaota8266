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

#include <stdio.h>
#include "lwip/tcp.h"
#include "lwip/init.h"
#include "lwip/timers.h"
#include "ets_alt_task.h"
#include "user_interface.h"
#include "lib/axtls/crypto/crypto.h"
#define MD5_CTX MD5_CTX
#include "../boot8266/etshal.h"
#include "../config.h"

#define OTA_START MAIN_APP_OFFSET

#define CHECK(v)     \
    if (v != ERR_OK) \
    printf(#v ": err\n")

static uint8_t MOD[] = MODULUS;
#define RSA_BLK_SIZE (sizeof(MOD) - 1)
#define OFFSET_TYPE uint32_t
#define PKT_OFFSET_SIZE sizeof(OFFSET_TYPE)

static OFFSET_TYPE ota_offset;
static uint32_t session_start_time;
static uint32_t last_pkt_time;
static RSA_CTX *rsa_context = NULL;

static char buf[4096];
static int buf_sz;

#define SOCKET struct tcp_pcb *

static void buf_init(void)
{
    buf_sz = 0;
    memset(buf, 0xff, sizeof(buf));
}

#define MP_FASTCODE(n) __attribute__((section(".iram0.text." #n))) n

void MP_FASTCODE(write_buf)(void)
{
    if (buf_sz > 0)
    {
        uint32_t off = OTA_START + ota_offset;
        if (off & (4096 - 1))
        {
            off &= ~(4096 - 1);
        }
        else
        {
            off -= 4096;
        }
        printf("Writing %d bytes of buf to %x\n", buf_sz, off);
        SPIEraseSector(off / 4096);
        SPIWrite(off, buf, sizeof(buf));
    }
    buf_init();
}

static void session_init(void)
{
    ota_offset = 0;
    session_start_time = system_get_time();
}

void timer_handler(void *arg)
{
    // printf("tick\n");

    if (ota_offset > 0 && system_get_time() - last_pkt_time > PKT_WAIT_MS * 1000)
    {
        printf("Next pkt wait timeout, rebooting\n");
        session_init();
        system_restart();
    }

    if (ota_offset == 0 && system_get_time() - session_start_time > IDLE_REBOOT_MS * 1000)
    {
        printf("OTA start timeout, rebooting\n");
        session_init();
        system_restart();
    }
    check_for_ap_clients();

    sys_timeout(1000, timer_handler, NULL);
}
void close_connection(SOCKET socket)
{
    printf("Closing connection\n");
    tcp_arg(socket, NULL);
    tcp_sent(socket, NULL);
    tcp_recv(socket, NULL);
    tcp_err(socket, NULL);
    tcp_poll(socket, NULL, 0);
    tcp_close(socket);
    wifi_station_set_reconnect_policy(true);
}

err_t message_sent(void *arg, SOCKET socket, uint16_t len)
{
    if (len != PKT_OFFSET_SIZE)
    {
        printf("Message not fully sent to remote client:\n    sent %d, expected %d\n", len, PKT_OFFSET_SIZE);
    }
    return ERR_OK;
}
err_t tcp_data_received(void *arg, SOCKET socket, struct pbuf *p, err_t error)
{
    if (error != ERR_OK)
        printf("Data received\n    code: %d\n", error);

    if (p == NULL)
    {
        // connection has been closed
        // set null all the callbacks associated with socket
        printf("Connection closed by client\n");
        close_connection(socket);
    }
    else
    {
        printf("Received data (%u/%u)\n", p->len, p->tot_len);
        last_pkt_time = system_get_time();
        // The package size must be at least the size of the 2 (uint16_t, the packet len) + signature
        if (p->len < PKT_OFFSET_SIZE + RSA_BLK_SIZE)
        {
            printf("Invalid package length: minimum %u", PKT_OFFSET_SIZE + RSA_BLK_SIZE);
        }
        else
        {
            // payload = (uint32)offset + data
            uint16_t payload_size = p->len - RSA_BLK_SIZE;

            // data size = payload size - 4 (from 4 bytes of uint32)
            uint16_t calculated_data_size = payload_size - PKT_OFFSET_SIZE;
            printf("Calculated data size: %u\n", calculated_data_size);

            uint8_t *data_pointer = p->payload + PKT_OFFSET_SIZE; // data start = payload start + 4
            uint8_t *rsa_block_pointer = data_pointer + calculated_data_size; // sig start = data start + data size
            uint8_t decrypted_signature[RSA_BLK_SIZE]; // p.payload[-RSA_BLK_SIZE:]
            uint8_t *hash_pointer = decrypted_signature;
            int decrypted_data_size = RSA_decrypt(rsa_context, rsa_block_pointer, decrypted_signature, RSA_BLK_SIZE, 0); // verify only?
            if (decrypted_data_size != SHA1_SIZE)
            {
                printf("Invalid hash size in signature\n    got: %d, expected: %d", decrypted_data_size, SHA1_SIZE);
            }
            else
            {
                //printf("Valid hash size in signature\n");
                SHA1_CTX sha_context;
                SHA1_Init(&sha_context);
                SHA1_Update(&sha_context, (uint8_t *)p->payload, payload_size);
                uint8_t calculated_hash[SHA1_SIZE];
                SHA1_Final(calculated_hash, &sha_context);

                // compare hash of message with calculated message hash
                if (memcmp(calculated_hash, hash_pointer, SHA1_SIZE) != 0)
                {
                    printf("Invalid SHA1\n");
                }
                else
                {
                    //printf("Valid SHA1\n");

                    // using this horrible thing here as
                    // OFFSET_TYPE received_offset = *(OFFSET_TYPE*)p->payload;
                    // was throwing a
                    // Fatal exception 9(LoadStoreAlignmentCause)
                    OFFSET_TYPE temp[0];
                    ((uint8_t *)temp)[0] = ((uint8_t *)p->payload)[0];
                    ((uint8_t *)temp)[1] = ((uint8_t *)p->payload)[1];
                    ((uint8_t *)temp)[2] = ((uint8_t *)p->payload)[2];
                    ((uint8_t *)temp)[3] = ((uint8_t *)p->payload)[3];
                    OFFSET_TYPE received_offset = temp[0];
                    if (ota_offset + calculated_data_size != received_offset)
                    {
                        printf("Invalid data offset\nCalculated: %u\nReceived:   %u\n", ota_offset + calculated_data_size, received_offset);
                        // resend ota_offset
                        uint16_t max_size = tcp_sndbuf(socket); // may not be used, as we only need to send 4 bytes
                        tcp_write(socket, &ota_offset, PKT_OFFSET_SIZE, TCP_WRITE_FLAG_COPY);
                        tcp_output(socket);
                    }
                    else
                    {
                        printf("Received offset: %u\n", received_offset);
                        if (calculated_data_size == 0)
                        {
                            printf("Buffer write\n");
                            write_buf();
                            printf("End of OTA. Booting new firmware\n\n\n\n");
                            session_init();
                            wifi_station_set_reconnect_policy(true);

#ifdef OTAOTA
                            printf("Setting magic word in RTC memory\n\n\n");
                            // set RTC memory to trigger normal OTA
                            long *userrtc = (long *)(0x60001000 + 512 + 20);
                            userrtc[0] = 0x746f6179;
                            userrtc[1] = 0x61746f61;
                            printf("Done!\n");
#endif
                            system_restart();
                        }
                        else
                        {
                            if (buf_sz + calculated_data_size > sizeof(buf))
                            {
                                int bytes_to_complete = sizeof(buf) - buf_sz;
                                memcpy(buf + buf_sz, data_pointer, bytes_to_complete);
                                ota_offset += bytes_to_complete;
                                buf_sz += bytes_to_complete;

                                printf("Buffer write\n");
                                write_buf();

                                int remaining = calculated_data_size - bytes_to_complete;
                                memcpy(buf, data_pointer + bytes_to_complete, remaining);
                                ota_offset += remaining;
                                buf_sz += remaining;
                            }
                            else
                            {
                                memcpy(buf + buf_sz, data_pointer, calculated_data_size);
                                ota_offset += calculated_data_size;
                                buf_sz += calculated_data_size;
                            }
                            printf("Buffer size: %u\n", buf_sz);

                            uint16_t max_size = tcp_sndbuf(socket); // may not be used, as we only need to send 4 bytes
                            tcp_write(socket, &ota_offset, PKT_OFFSET_SIZE, TCP_WRITE_FLAG_COPY);
                            tcp_output(socket);

                            if (buf_sz == sizeof(buf))
                            {
                                printf("Buffer write\n");
                                write_buf();
                            }
                        }
                    }
                }
            }
        }
        pbuf_free(p);
        tcp_recved(socket, p->len);
        printf("\n\n");
    }
    return ERR_OK;
}
err_t connection_poll(void *arg, SOCKET socket)
{
    //printf("Polling\n");
    return ERR_OK;
}
void check_for_ap_clients()
{
    if (wifi_softap_get_station_num() > 0)
    {
        printf("There are clients connected to softAP. Disabling auto reconnect\nClients: %u\n", wifi_softap_get_station_num());
        wifi_station_set_reconnect_policy(false);
    }
    else
    {
        wifi_station_set_reconnect_policy(true);
    }
}
void connection_error(void *arg, err_t error)
{
    printf("\n----\nError!\n----\ncode: %d\n", error);
    wifi_station_set_reconnect_policy(true);
}
err_t tpc_client_accepted(void *arg, SOCKET socket, err_t error)
{
    printf("Client accepted (code: %d)\n", error);
    // arg is not used as tcp_arg wasn't called

    check_for_ap_clients();

    // callback for data received
    tcp_recv(socket, tcp_data_received);

    // callback for polling
    tcp_poll(socket, connection_poll, 2 * 5);

    // callback for error
    tcp_err(socket, connection_error);

    // callback for message sent ack
    tcp_sent(socket, message_sent);

    uint16_t version[3] = {VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH}; // 6 bytes
    tcp_write(socket, version, 6, TCP_WRITE_FLAG_COPY);
    tcp_output(socket);

    return ERR_OK;
}

void ota_start(void)
{

#ifdef OTAOTA
    printf("starting OTAOTA-TCP\n");

    long *userrtc = (long *)(0x60001000 + 512 + 20);
    printf("Enabling normal OTA on next boot\n");
    userrtc[0] = 0x746f6179;
    userrtc[1] = 0x61746f61;
#else
    printf("starting OTA-TCP\n");
#endif

    printf("Version %d.%d.%d\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);

    session_init();
    buf_init();

    RSA_pub_key_new(&rsa_context, MOD, sizeof(MOD) - 1, (uint8_t *)"\x03", 1);
    printf("rsa_context = %p\n", rsa_context);

    printf("Initializing lwip\n");
    lwip_init();

    printf("Check timeouts\n");
    // lwip timeout check
    sys_check_timeouts();

    printf("Creating socket\n");
    // create new connection control block?
    SOCKET tcp_socket = tcp_new();

    if (tcp_socket == NULL)
    {
        printf("Socket creation failed\n");
        // no memory available for allocation of connection control block
    }
    else
    {
        printf("Socket created. Binding\n");
        // bind the address to the block

#ifdef OTAOTA
        err_t error_code = tcp_bind(tcp_socket, IPADDR_ANY, 8268);
#else
        err_t error_code = tcp_bind(tcp_socket, IP_ADDR_ANY, 8267);
#endif

        if (error_code == ERR_USE)
        {
            // port already in use

            printf("Address already in use\n");
        }
        else
        {
            printf("Bound\n");
            // port is available. error_code = ERR_OK

            // sets the socket to listen mode. Deallocates old
            // socket and allocates new one that is smaller
            tcp_socket = tcp_listen(tcp_socket);
            if (tcp_socket == NULL)
            {
                printf("Socket failed to setup in listen mode\n");
                // no memory available for allocation of new
                // socket. old tcp_socket has not been
                // deallocated in this case, causing memory
                // leak
            }
            else
            {
                printf("Socket in listen mode\n");
                tcp_accept(tcp_socket, tpc_client_accepted);
            }
        }
    }

    sys_timeout(1000, timer_handler, NULL);

    while (1)
    {
        ets_loop_iter();
    }
}
