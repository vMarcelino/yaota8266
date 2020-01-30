#!/usr/bin/env python3
import sys
import struct
import socket
import time
import hashlib
import argparse
import requests
import os

#from Crypto.Cipher import AES
import rsa_sign

# How many firmware data bytes are included in each packet.
# Set a conservative default. There were issues reported that
# UDP packet larger than 548 bytes don't get thru. Unfortunately,
# that means that even 512 payload bytes + headers don't fit.

BLK_SIZE = 468

AES_IV = b"\0" * 16
AES_KEY = b"\x01" * 16


# rsa_key = None
# last_aes_key = None
# last_seq = 0
# rexmit = 0
class _OTA:
    def __init__(self, device_name, device_address, file, port=8267, log=print):
        self.rsa_key = rsa_sign.load_key(log=log)
        self.device_name = device_name
        self.device_address = device_address
        self.port = port
        self.file = file
        self.log = log

        self.retry_forever()

    def retry_forever(self):
        while True:
            try:
                self.live_ota()
                break
            except KeyboardInterrupt:
                self.log('operation canelled for', self.device_name)
                break
            except Exception as e:
                self.log('error detected:', e)

        self.log('done:', self.device_name)

    def live_ota(self):
        raise NotImplementedError

    def activate_ota(self):
        try:
            r = requests.get(f'http://{self.device_address}/ota', timeout=0.2)
            self.log(r)
        except:
            self.log('OTA start request fail')
            pass


class OTA_TCP(_OTA):
    def live_ota(self):
        self.activate_ota()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(2)
        self.socket.connect((self.device_address, self.port))
        self.socket.settimeout(5)
        self.offset = 0

        try:
            version_bytes = self.socket.recv(256)
            version_major = int.from_bytes(version_bytes[0:2], byteorder='little', signed=False)
            version_minor = int.from_bytes(version_bytes[2:4], byteorder='little', signed=False)
            version_patch = int.from_bytes(version_bytes[4:6], byteorder='little', signed=False)
            self.log(f'OTA version {version_major}.{version_minor}.{version_patch}')
        except socket.timeout:
            self.log('No version detected. Continuing')

        except Exception as e:
            self.log(type(e), e)

        self.socket.settimeout(30)

        with open(self.file, "rb") as f:
            f.seek(0, os.SEEK_END)
            total_size = f.tell()
            f.seek(0)
            while True:
                self.log(f'{100*self.offset/total_size:.02f}%')
                chunk = f.read(BLK_SIZE)
                if not chunk:
                    break
                self.offset += len(chunk)  # starts with id 1
                received_offset = self.send(chunk)
                if received_offset != self.offset:
                    self.log('offset mismatch:')
                    self.log('current: ', self.offset)
                    self.log('received:', received_offset)
                    self.offset = received_offset
                    f.seek(self.offset)

        self.send_ota_end()
        self.socket.close()
        self.log("Done", self.device_name)

    def send(self, chunk, has_response: bool = True) -> int:
        pkt = self.make_pkt(chunk)
        #self.log('sending:')
        #self.log(pkt)
        self.socket.sendall(pkt)
        if has_response:
            response = self.socket.recv(128)
            received_offset = int.from_bytes(response, byteorder='little', signed=False)
            return received_offset
        else:
            return

    def make_pkt(self, chunk: bytes) -> bytes:
        pkt_offset = (self.offset).to_bytes(4, byteorder='little')
        #self.log('offset:', pkt_offset)
        pkt = pkt_offset + chunk
        aes_key = AES_KEY
        #aes = AES.new(aes_key, AES.MODE_CBC, AES_IV)
        #pad_len = (16 - len(pkt) % 16) % 16
        #pkt += b"\0" * pad_len
        #pkt = aes.encrypt(pkt)

        digest = hashlib.sha1(pkt).digest()
        sig = rsa_sign.sign(self.rsa_key, aes_key + digest)

        return pkt + sig

    def send_ota_end(self):
        self.send(b'', has_response=False)


class OTA_UDP(_OTA):
    def live_ota(self):
        self.rexmit = 0
        self.last_seq = 0

        self.activate_ota()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect((self.device_address, 8266))
        self.socket.settimeout(0.5)

        offset = 0
        with open(self.file, "rb") as f:
            f.seek(0, os.SEEK_END)
            total_size = f.tell()
            f.seek(0)
            while True:
                self.log(f'{100*offset/total_size:.02f}%')
                time.sleep(0.05)
                chunk = f.read(256)
                if not chunk:
                    break
                pkt = self.make_pkt(offset, chunk)
                self.send_recv(offset, pkt, len(chunk))
                offset += len(chunk)

        self.send_ota_end()
        self.log("Done, rexmits: %d" % self.rexmit, self.device_name)

    def make_pkt(self, offset, data):
        pkt = struct.pack("<HHI", 0, len(data), offset) + data
        pkt = self.add_digest(pkt)
        return pkt

    def add_digest(self, pkt):
        aes_key = AES_KEY
        #aes = AES.new(aes_key, AES.MODE_CBC, AES_IV)
        pad_len = (16 - len(pkt) % 16) % 16
        pkt += b"\0" * pad_len
        #pkt = aes.encrypt(pkt)

        digest = hashlib.sha1(pkt).digest()
        sig = rsa_sign.sign(self.rsa_key, aes_key + digest)
        self.last_seq += 1
        return struct.pack("<I", self.last_seq) + pkt + sig

    def send_recv(self, offset, pkt, data_len):
        errors = 0
        max_errors = 50
        while errors < max_errors:
            try:
                #self.log("Sending #%d" % self.last_seq)
                #self.log("send:", pkt)
                self.socket.send(pkt)
                self.log('s', end=' ')
                resp = self.socket.recv(1024)
                #self.log("resp:", resp, len(resp))
                resp_seq = struct.unpack("<I", resp[:4])[0]
                self.log('received req num:', resp_seq, end=' ')
                if resp_seq != self.last_seq:
                    self.log("Unexpected seq no: %d (expected: %d)" % (resp_seq, self.last_seq), self.device_name)
                    errors += 1
                    continue

                resp = resp[4:]
                resp_op, resp_len, resp_off = struct.unpack("<HHI", resp[:8])
                #self.log("resp:", (resp_seq, resp_op, resp_len, resp_off), self.device_name)
                if resp_off != offset or resp_len != data_len:
                    self.log("Invalid resp", self.device_name)
                    errors += 1
                    continue
                self.log('ok')
                break
            except socket.timeout:
                # For such packets we don't expect reply
                if offset == 0 and data_len == 0:
                    break
                self.log(f"timeout #{self.last_seq}, ({errors}/{max_errors})", self.device_name)
                self.rexmit += 1
                errors += 1

        if errors >= max_errors:
            raise Exception('Could not send package. Restarting')

    def send_ota_end(self):
        # Repeat few times to minimize chance of being lost
        for _ in range(3):
            pkt = self.make_pkt(0, b"")
            self.socket.send(pkt)
            time.sleep(0.1)


if __name__ == "__main__":
    OTA_TCP('Fan', '192.168.4.1', '../../bin/firmware-ota-Fan.bin')
    #OTA_TCP('Fan', '192.168.4.1', '../otaonly.bin')