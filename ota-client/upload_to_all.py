import ping
import os
import ota_client
import threading
import curses
import textwrap

with open("version.txt") as f:
    current_version = f.read()

ota = os.path.abspath(os.path.join('..', '..', 'bin', 'ota.bin'))
ota_ota = os.path.abspath(os.path.join('..', '..', 'bin', 'otaota.bin'))


def calculate_bin_file(device_name):
    file = os.path.join('..', '..', 'bin', 'firmware-ota-' + device_name + '.bin')
    file = os.path.abspath(file)
    return file


def make_new_print(window):
    window.idlok(True)
    window.immedok(True)
    window.scrollok(True)
    window.clear()

    def new_print(*args, end='\n'):
        text = ' '.join(map(str, args))
        y, x = window.getmaxyx()
        wrapped_text_lines = textwrap.wrap(text, x - 1)
        wrapped_text = '\n'.join(wrapped_text_lines) + end
        wrapped_text = text + end
        window.addstr(wrapped_text)

    return new_print


def upload_to_device(device, window):
    print = make_new_print(window)

    host_version = device['version']
    if host_version != current_version:
        print(f'>> {device["host"]} is outdated. Updating')
        file = calculate_bin_file(device['host'])
        print(file)
        if os.path.isfile(file):
            # port 8266 (TCP) = webrepl
            # port 8266 (UDP) = OTA-UDP: old protocol. to update the main firmware
            # port 8267 = OTA-TCP: to update the main firmware
            # port 8268 = OTA-OTA-TCP: to update the OTA firmware

            if host_version == 'Pre-Alpha':
                print(f'>> {device["host"]} OTA is outdated. Updating')
                ota_client.OTA_UDP(device['host'], device['address'], ota_ota, log=print)  # port=8266, install OTA updater
                ota_client.OTA_TCP(device['host'], device['address'], ota, port=8268, log=print)  # update OTA

            ota_client.OTA_TCP(device['host'], device['address'], file, port=8267, log=print)  # update firmware

        else:
            print('file not found')
    else:
        print(f'>> {device["host"]} is up-to-date')


def process_devices(screen, devices):
    log = make_new_print(screen)
    asynchronous = not os.path.isfile('sync.cfg')
    if devices:
        cols = curses.COLS // len(devices)

        threads = []

        for i, device in enumerate(devices):
            window = curses.newwin(curses.LINES, cols, 0, cols * i)
            t = threading.Thread(target=upload_to_device, args=(device, window))
            t.start()
            threads.append(t)
            if not asynchronous:
                t.join()

        for t in threads:
            t.join()


def main():
    devices = ping.get_devices(ask_for_ip=True, local_ip=None, broadcast_ip=None, my_port=22256, all_interfaces=True, show_raw_fields=False)
    curses.wrapper(process_devices, devices)


if __name__ == "__main__":
    main()