# -*- coding: utf-8 -*-
"""
Created on Tue May 22 12:12:42 2018

@author: Victor Marcelino
"""
import subprocess
import threading
import socket
import travel_backpack
import time
import netifaces
import copy
from functools import wraps


def ping2(ips):
    from multiping import MultiPing, multi_ping
    import copy

    receive_timeout = 2

    # Create a MultiPing object to test three hosts / addresses
    mp = MultiPing(ips)

    # Send the pings to those addresses
    mp.send()

    # With a 5 second timout, wait for responses (may return sooner if all
    # results are received).
    responses, no_responses = mp.receive(receive_timeout)
    #travel_backpack.pp({'responses':responses, 'no responses':no_responses})
    if responses is None:
        responses = {}

    #responses = copy.deepcopy(responses)

    #for i in range(5):
    while no_responses:
        print('No responses:')
        travel_backpack.pp(no_responses)
        if no_responses:
            mp = MultiPing(no_responses)
            mp.send()
            new_responses, no_responses = mp.receive(receive_timeout)
            if new_responses is not None:
                responses.update(new_responses)
            #travel_backpack.pp({'responses':responses, 'no responses':no_responses})
        else:
            break

    #print('final:')
    #travel_backpack.pp({'responses':responses, 'no responses':no_responses})
    return responses, no_responses

    #return mp.receive(3)
    #return multi_ping(ips, timeout=10, retry=10)


def get_ipv4_addresses(print_all=False, print_addresses=False):
    ipv4_interfaces = []
    import os
    is_nt = os.name == 'nt'
    address_familys = {netifaces.AF_LINK: 'Link Layer Address', netifaces.AF_INET: 'Internet IPv4 Address', netifaces.AF_INET6: 'Internet IPv6 Address'}
    #list interfaces
    interfaces = netifaces.interfaces()
    if is_nt:
        import wmi
        import pythoncom
        pythoncom.CoInitialize()
        c = wmi.WMI()
        query = "select * from Win32_NetworkAdapter where GUID is not null"
        interface_names = c.query(query)
        #travel_backpack.pp(interface_names)
    for interface in interfaces:
        if print_all: print('\nInterface:', end='')
        if is_nt:
            interface_name_info = next((interface_info for interface_info in interface_names if interface_info.GUID == interface), 'Not Available')
            if type(interface_name_info) is str:
                if print_all: print(interface_name_info + ' ', end='')
            else:
                if print_all: print(f'{interface_name_info.NetConnectionID} ({interface_name_info.Name}) ', end='')
        if print_all: print(interface, end='')
        if print_all: print()
        interface_addresses = netifaces.ifaddresses(interface)
        #link_layer_address = addresses[netifaces.AF_LINK]
        #internet_address = addresses[netifaces.AF_INET]
        #internet_ipv6_address = addresses[netifaces.AF_INET6]
        if netifaces.AF_INET in interface_addresses:
            family_addresses = interface_addresses[netifaces.AF_INET]
            for family_address in family_addresses:
                try:
                    ipv4_interfaces.append([family_address['addr'], family_address['broadcast']])
                except Exception as ex:
                    if print_all: print('exception in ping:', type(ex), ex)

        for address_family, family_addresses in interface_addresses.items():
            if print_all: print('\t', address_familys[address_family])
            for family_address_index, family_address in enumerate(family_addresses):
                for address_name, address in family_address.items():
                    if print_all: print(f'\t\t{family_address_index}:', address_name, address)

    if print_all: print()
    if print_addresses: travel_backpack.pp(ipv4_interfaces)
    return ipv4_interfaces


def get_default_addresses(print_all=True, print_ip_addresses=True):
    if print_all:
        get_ipv4_addresses(True)
    #get default address
    gateway, interface = netifaces.gateways()['default'][netifaces.AF_INET]

    #get interface addresses
    interface_addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET]
    for addr in interface_addresses:
        try:
            tmp_loc_ip, tmp_brdc_ip = addr['addr'], addr['broadcast']
            local_ip, broadcast_ip = tmp_loc_ip, tmp_brdc_ip
            if print_ip_addresses:
                print('local:    ', local_ip)
                print('broadcast:', broadcast_ip)

        except:
            pass
    return gateway, local_ip, broadcast_ip


def ping(hostname, return_list=None, count=1):
    proc = subprocess.Popen(f'ping -n {count} {hostname}', shell=True, stdout=subprocess.PIPE)
    response = (proc.communicate()[0].decode("utf-8")).replace('\r', '')
    print(response)
    broken_ping, _ = response.split('\n\nPing statistics for')
    _, p = broken_ping.split('bytes of data:\n')
    p = p.split('\n')
    if return_list is None:
        return_list = []
    for el in p:
        print('->', el)
        if 'ms' not in el:
            return_list.append(None)

        else:
            return_list.append(int(el.split('=')[2].split('ms')[0]))

    return return_list


class Ping_thread(threading.Thread):
    def __init__(self, hostname, return_arr=None, count=1):
        threading.Thread.__init__(self)
        self.hostname = hostname
        self.count = count
        self.return_arr = return_arr if return_arr is not None else []
        self.result_ready = False

    def run(self):
        self.result_ready = False
        ping(self.hostname, self.return_arr, self.count)
        self.result_ready = True


@travel_backpack.threadpool
def listen_udp(port=2256,
               timeout=2,
               show_received_UDP_messages=False,
               show_sent_UDP_messages=True,
               show_connected_plugs_always=False,
               show_raw_fields=False,
               log=print):
    devices = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        #with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as sock:
        sock.settimeout(timeout)
        sock.bind(('', port))
        if show_connected_plugs_always or show_received_UDP_messages or show_sent_UDP_messages:
            log('listening on', port)

        ips_to_ping = []
        try:
            while True:
                #log('awaiting messages')
                data, addr = sock.recvfrom(65535)  # buffer size is 1024 bytes
                data = data.decode('utf-8')
                #log(f'received from {addr}')
                plug_info = {}
                try:
                    fields = data.split('\n')
                    log(fields)
                    for field in fields:
                        try:
                            key, value = field.split('=')
                            plug_info[key] = value
                            if show_received_UDP_messages:
                                log(key, '=', value)

                        except ValueError:
                            if show_received_UDP_messages:
                                log(f'unknown field {addr}: {field}')
                except ValueError:
                    if show_received_UDP_messages:
                        log(f'Invalid data {addr}:  {data}')

                if show_connected_plugs_always:
                    log(travel_backpack.bcolors.OKGREEN + plug_info['host'] + ' online' + travel_backpack.bcolors.ENDC)

                in_devices = False
                for d in devices:
                    if 'mac_address' in d:
                        if plug_info.get('mac_address', None) == d['mac_address']:
                            in_devices = True
                    else:
                        if plug_info.get('host', None) == d['host']:
                            in_devices = True

                if not in_devices:
                    devices.append(plug_info)
                    #for k, v in plug_info.items():
                    #    log(f'\t{k}'.ljust(10), '=', v)

        except socket.timeout:
            if show_connected_plugs_always or show_received_UDP_messages or show_sent_UDP_messages:
                log('done listenning')

    return devices


def get_devices(local_ip=None,
                broadcast_ip=None,
                my_port=2256,
                broadcast_port=2255,
                timeout=4,
                all_interfaces=True,
                ping_after=True,
                ask_for_ip=False,
                broadcast_count=3,
                time_between_broadcasts=1,
                time_between_inferface_broadcasts=0.01,
                show_received_UDP_messages=False,
                show_sent_UDP_messages=True,
                show_connected_plugs_always=False,
                show_all_hosts_info=True,
                show_raw_fields=False,
                continue_on_ping_fail=True,
                log=print):

    # Setup addresses
    if all_interfaces:
        addresses = get_ipv4_addresses(False)

    else:
        if local_ip is None or broadcast_ip is None:
            gateway, t_local_ip, t_broadcast_ip = get_default_addresses(print_all=True, print_ip_addresses=True)
            if local_ip is None: local_ip = t_local_ip
            if broadcast_ip is None: broadcast_ip = t_broadcast_ip

        if ask_for_ip:
            if not travel_backpack.binary_user_question(f'send {local_ip}:{my_port} to {broadcast_ip}:{broadcast_port}?'):
                local_ip = travel_backpack.check_var_input('Local IP:')
                broadcast_ip = travel_backpack.check_var_input('Broadcast IP:')
                if travel_backpack.binary_user_question(f'Change ports?', default=False):
                    my_port = travel_backpack.check_var_input('Local receiving port:')
                    broadcast_port = travel_backpack.check_var_input('Broadcast sending port:')

        addresses = [[local_ip, broadcast_ip]]

    # Start listenner
    async_result = listen_udp(
        my_port, timeout, show_received_UDP_messages, show_sent_UDP_messages, show_connected_plugs_always, show_raw_fields=show_raw_fields, log=log)

    if show_connected_plugs_always or show_received_UDP_messages or show_sent_UDP_messages:
        log('Starting UDP probing with', broadcast_count, 'tries, timeout =', timeout)

    # Start broadcasts
    for i in range(broadcast_count):
        for local_ip, broadcast_ip in addresses:
            message = f'{local_ip}:{my_port}'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock_send:
                sock_send.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock_send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock_send.sendto(message.encode('utf-8'), (broadcast_ip, broadcast_port))

            if show_sent_UDP_messages:
                log(f'sent {message}'.ljust(25, '-') + f'{broadcast_ip}:{broadcast_port}')

            time.sleep(time_between_inferface_broadcasts)

        if show_connected_plugs_always or show_received_UDP_messages or show_sent_UDP_messages:
            log(f'done ({i+1} out of {broadcast_count})')

        time.sleep(time_between_broadcasts)

    devices = async_result.result()
    #devices = listen_udp(my_port, timeout)

    devices.sort(key=lambda x: x['host'])
    if len(devices) > 0:
        if ping_after:
            try:
                log('pinging')
                responses, no_responses = ping2([device['address'] for device in devices])
                log('responses:')
                travel_backpack.pp(responses)

                for device in devices:
                    device['ping'] = responses.get(device['address'], None)
                    if device['ping'] is not None:
                        device['ping'] = int(device['ping'] * 1000)
                log('no responses:')
                travel_backpack.pp(no_responses)
            except Exception as e:
                if not continue_on_ping_fail:
                    raise e

        if show_all_hosts_info:
            log('\n')
            temp_devices = copy.deepcopy(devices)
            for device in temp_devices:
                if travel_backpack.supports_color():
                    log(f"\n{travel_backpack.bcolors.OKGREEN}{device.pop('host')}{travel_backpack.bcolors.ENDC}:")
                else:
                    log(f"\n{device.pop('host')}:")
                travel_backpack.pp(device)

    else:
        log('No devices online')

    return devices


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-l', '--local', type=str, help='local ip to be sent in message. Used only if single interface is set', default=None)
    parser.add_argument('-b', '--broadcast', type=str, help='broadcast ip to be able to send the message. Used only if single interface is set', default=None)
    parser.add_argument('-p', '--port', type=int, help='the port used to receive the messages', default=2256)
    parser.add_argument('-i', '--single_interface', action='store_true', help='to send broadcast a single interface')
    parser.add_argument('-f', '--force', action='store_true', help='to force upload of new firmwares regardless of the version')
    parser.add_argument('-v', '--version', type=str, help='version to be checked against', default=None)
    #parser.add_argument('-a', '--ask_ip', action='store_true', help='to prompt ip')
    parser.add_argument('-r', '--raw_response', action='store_true', help='to show raw plug response')
    args = parser.parse_args()

    get_devices(
        ask_for_ip=True,
        local_ip=args.local,
        broadcast_ip=args.broadcast,
        my_port=args.port,
        all_interfaces=not args.single_interface,
        show_raw_fields=args.raw_response)
    input('any key to continue')
