import sys
import os
import random
import time
import datetime
import threading
import json
import pcapy
import dpkt

# mac
interface = 'en0'
enable_monitor  = 'tcpdump -i en0 -Ic1 -py IEEE802_11'
disable_monitor = 'tcpdump -i en0 -Ic1'
change_channel  = 'airport en0 -c{}'

# linux
# interface = 'wlan1mon'
# enable_monitor  = 'ifconfig wlan1 down; iw dev wlan1 interface add wlan1mon type monitor; ifconfig wlan1mon down; iw dev wlan1mon set type monitor; ifconfig wlan1mon up'
# disable_monitor = 'iw dev wlan1mon del; ifconfig wlan1 up'
# change_channel  = 'iw dev wlan1mon set channel {}'

channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] # 2.4GHz only

store = {}

def start():
    os.system(enable_monitor)
    rotating = rotator(channels, change_channel)
    writing  = writer()
    try: sniff(interface)
    except SystemError: sys.exit()
    except KeyboardInterrupt: sys.exit()
    finally:
        writing.set()
        rotating.set()
        os.system(disable_monitor)

def rotator(channels, change_channel):
    def rotate(stop):
        while not stop.is_set():
            channel = random.choice(channels)
            print('\nChanging to channel ' + str(channel) + '\n')
            os.system(change_channel.format(channel))
            time.sleep(1) # seconds
    stop = threading.Event()
    threading.Thread(target=rotate, args=[stop]).start()
    return stop

def writer():
    def write(stop):
        while not stop.is_set():
            print('\nWriting to file...\n')
            with open('wifispy.json', 'w') as file: json.dump(store, file)
            time.sleep(1) # seconds
    stop = threading.Event()
    threading.Thread(target=write, args=[stop]).start()
    return stop

def add(address, timestamp):
    if address in store:
        thisTimestamp = datetime.datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f')
        lastSessionTimestamp = datetime.datetime.strptime(store[address][-1]['lastSeen'], '%Y-%m-%dT%H:%M:%S.%f')
        if (thisTimestamp - lastSessionTimestamp).total_seconds() > 60 * 60: # longer than an hour ago
            store[address].append({ 'firstSeen': timestamp, 'lastSeen': timestamp })
        else: store[address][-1]['lastSeen'] = timestamp
    else: store[address] = [{ 'firstSeen': timestamp, 'lastSeen': timestamp }]

def to_address(address): # decode a MAC or BSSID address
    return ':'.join('%02x' % ord(b) for b in address)

def sniff(interface):
    max_packet_size = 256 # bytes
    promiscuous = 0 # boolean masquerading as an int
    timeout = 100 # milliseconds
    packets = pcapy.open_live(interface, max_packet_size, promiscuous, timeout)
    packets.setfilter('') # bpf syntax (empty string = everything)
    def loop(header, data):
        timestamp = datetime.datetime.now().isoformat()
        try:
            packet = dpkt.radiotap.Radiotap(data)
            # packet_signal = -(256 - packet.ant_sig.db) # dBm (doesn't seem to work though)
            frame = packet.data
            if frame.type == dpkt.ieee80211.MGMT_TYPE:
                subtype = str(frame.subtype)
                source_address = to_address(frame.mgmt.src)
                destination_address = to_address(frame.mgmt.dst)
                ap_address = to_address(frame.mgmt.bssid)
                ap_name = frame.ssid.data if hasattr(frame, 'ssid') else '(n/a)'
                add(source_address, timestamp)
                print('[MANAGEMENT] ' + subtype + ' * ' + source_address + ' -> ' + destination_address + ' * ' + ap_name)
            elif frame.type == dpkt.ieee80211.CTL_TYPE:
                subtype = str(frame.subtype)
                print('[CONTROL   ] ' + subtype)
            elif frame.type == dpkt.ieee80211.DATA_TYPE:
                subtype = str(frame.subtype)
                source_address = to_address(frame.data_frame.src)
                destination_address = to_address(frame.data_frame.dst)
                ap_address = to_address(frame.data_frame.bssid) if hasattr(frame.data_frame, 'bssid') else '(n/a)'
                add(source_address, timestamp)
                print('[DATA      ] ' + subtype + ' * ' + source_address + ' -> ' + destination_address + ' * ' + ap_address)
        except:
            print('[ERROR PARSING PACKET]')
    packets.loop(-1, loop)

start()
