import sys
import os
import random
import time
import datetime
import multiprocessing
import sqlite3
import pcapy
import dpkt

# mac
# interface = 'en0'
# monitor_enable  = 'tcpdump -i en0 -Ic1 -py IEEE802_11'
# monitor_disable = 'tcpdump -i en0 -Ic1'
# change_channel  = 'airport en0 channel {}'

# linux
interface = 'wlan1mon'
monitor_enable  = 'ifconfig wlan1 down; iw dev wlan1 interface add wlan1mon type monitor; ifconfig wlan1mon down; iw dev wlan1mon set type monitor; ifconfig wlan1mon up'
monitor_disable = 'iw dev wlan1mon del; ifconfig wlan1 up'
change_channel  = 'iw dev wlan1mon set channel {}'

channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] # 2.4GHz only

queue = multiprocessing.Queue()

def start():
    os.system(monitor_enable)
    stop_rotating = rotator(channels, change_channel)
    stop_writing  = writer()
    try: sniff(interface)
    except SystemError: sys.exit()
    except KeyboardInterrupt: sys.exit()
    finally:
        stop_writing.set()
        stop_rotating.set()
        os.system(monitor_disable)

def rotator(channels, change_channel):
    def rotate(stop):
        while not stop.is_set():
            channel = random.choice(channels)
            print('\nChanging to channel ' + str(channel) + '\n')
            os.system(change_channel.format(channel))
            time.sleep(1) # seconds
    stop = multiprocessing.Event()
    multiprocessing.Process(target=rotate, args=[stop]).start()
    return stop

def writer():
    db = sqlite3.connect('wifispy.sqlite3')
    def write(stop):
        while not stop.is_set():
            print('\nWriting to database...\n')
            cursor = db.cursor()
            for i in range(0, queue.qsize()):
                item = queue.get_nowait()
                cursor.execute("""insert into packets values (:address, :timestamp)""", item)
            db.commit()
            cursor.close()
            time.sleep(1) # seconds
    cursor = db.cursor()
    cursor.execute("""create table if not exists packets (address text, timestamp timestamp)""")
    db.commit()
    cursor.close()
    stop = multiprocessing.Event()
    multiprocessing.Process(target=write, args=[stop]).start()
    return stop

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
            packet_signal = -(256 - packet.ant_sig.db) # dBm
            frame = packet.data
            if frame.type == dpkt.ieee80211.MGMT_TYPE:
                subtype = str(frame.subtype)
                source_address = to_address(frame.mgmt.src)
                destination_address = to_address(frame.mgmt.dst)
                ap_address = to_address(frame.mgmt.bssid)
                ap_name = frame.ssid.data if hasattr(frame, 'ssid') else '(n/a)'
                queue.put({ 'address': source_address, 'timestamp': timestamp })
                print('[MANAGEMENT] ' + subtype + ' * ' + str(packet_signal) + 'dBm * ' + source_address + ' -> ' + destination_address + ' * ' + ap_name)
            elif frame.type == dpkt.ieee80211.CTL_TYPE:
                subtype = str(frame.subtype)
                print('[CONTROL   ] ' + subtype + ' * ' + str(packet_signal) + 'dBm')
            elif frame.type == dpkt.ieee80211.DATA_TYPE:
                subtype = str(frame.subtype)
                source_address = to_address(frame.data_frame.src)
                destination_address = to_address(frame.data_frame.dst)
                ap_address = to_address(frame.data_frame.bssid) if hasattr(frame.data_frame, 'bssid') else '(n/a)'
                queue.put({ 'address': source_address, 'timestamp': timestamp })
                print('[DATA      ] ' + subtype + ' * ' + str(packet_signal) + 'dBm * ' + source_address + ' -> ' + destination_address + ' * ' + ap_address)
        except:
            print('[ERROR PARSING PACKET]')
    packets.loop(-1, loop)

start()
