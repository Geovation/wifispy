import sys
import os
import random
import time
import multiprocessing
import binascii
import pcapy
import impacket
import impacket.ImpactDecoder

# mac
interface = 'en0'
enable_monitor  = 'tcpdump -i en0 -Ic1 -py IEEE802_11'
disable_monitor = 'tcpdump -i en0 -Ic1'
change_channel  = 'airport -c{}'

# linux
interface = 'wlan1'
enable_monitor  = 'ifconfig wlan1 down; iw dev wlan1 interface add mon0 type monitor; ifconfig mon0 down; iw dev mon0 set type monitor; ifconfig mon0 up'
disable_monitor = 'iw mon0 del'
change_channel  = 'iw dev mon0 set channel {}'

channels = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, # 2.4GHz
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161 # 5GHz
]

def start():
    os.system(enable_monitor)
    rotator(channels, change_channel)
    try: sniff(interface)
    except BaseException as e: sys.exit(e)
    finally: os.system(disable_monitor)

def rotator(channels, change_channel):
    def hop():
        while True:
            try:
                channel = random.choice(channels)
                print('Changing to channel ' + str(channel) + '...')
                os.system(change_channel.format(channel))
                time.sleep(1) # seconds
            except BaseException as e: sys.exit(e)
    multiprocessing.Process(target=hop).start()

def to_address(array): # decode a MAC or BSSID address
    hexes = iter(binascii.hexlify(array))
    return ':'.join(a + b for a, b in zip(hexes, hexes))

def sniff(interface):
    max_packet_size = 256 # bytes
    promiscuous = 0 # boolean masquerading as an int
    timeout = 100 # milliseconds
    packets = pcapy.open_live(interface, max_packet_size, promiscuous, timeout)
    packets.setfilter('') # bpf syntax (empty string = everything)
    decoder = impacket.ImpactDecoder.RadioTapDecoder()
    def loop(header, data):
        print('Looping...')
        packet = decoder.decode(data)
        frame = packet.child()
        if frame.get_type() == impacket.dot11.Dot11Types.DOT11_TYPE_MANAGEMENT:
            body = frame.child()
            body_source = to_address(body.get_source_address())
            body_destination = to_address(body.get_destination_address())
            body_bssid = to_address(body.get_bssid()) # access point address
            request = body.child()
            request_type = request.__class__.__name__
            print('[MANAGEMENT FRAME]  ' + request_type + ' * ' + body_bssid + ' * ' + body_source + ' => ' + body_destination)
        elif frame.get_type() == impacket.dot11.Dot11Types.DOT11_TYPE_CONTROL:
            print('[CONTROL FRAME]')
        elif frame.get_type() == impacket.dot11.Dot11Types.DOT11_TYPE_DATA:
            print('[DATA FRAME]')
    packets.loop(-1, loop)

start()
