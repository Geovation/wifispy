import sys
import os
import logging
import traceback
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
    logging.basicConfig(filename='wifispy.log', format='%(levelname)s:%(message)s', level=logging.INFO)
    os.system(monitor_enable)
    stop_rotating = rotator(channels, change_channel)
    stop_writing  = writer()
    try: sniff(interface)
    except KeyboardInterrupt: sys.exit()
    finally:
        stop_writing.set()
        stop_rotating.set()
        os.system(monitor_disable)

def rotator(channels, change_channel):
    def rotate(stop):
        while not stop.is_set():
            try:
                channel = random.choice(channels)
                logging.info('Changing to channel ' + str(channel))
                os.system(change_channel.format(channel))
                time.sleep(1) # seconds
            except KeyboardInterrupt: pass
    stop = multiprocessing.Event()
    multiprocessing.Process(target=rotate, args=[stop]).start()
    return stop

def writer():
    db = sqlite3.connect('wifispy.sqlite3')
    def write(stop):
        while not stop.is_set():
            try:
                logging.info('Writing...')
                cursor = db.cursor()
                for _ in range(0, queue.qsize()):
                    item = queue.get_nowait()
                    insert = (
                        "insert into packets values"
                        "("
                        ":timestamp,"
                        ":type,"
                        ":subtype,"
                        ":strength,"
                        ":source_address,"
                        ":destination_address,"
                        ":access_point_name,"
                        ":access_point_address"
                        ")"
                    )
                    cursor.execute(insert, item)
                db.commit()
                cursor.close()
                time.sleep(1) # seconds
            except KeyboardInterrupt: pass
    cursor = db.cursor()
    create = (
        "create table if not exists packets"
        "("
        "timestamp,"
        "type,"
        "subtype,"
        "strength,"
        "source_address,"
        "destination_address,"
        "access_point_name,"
        "access_point_address"
        ")"
    )
    cursor.execute(create)
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
                record = {
                    'timestamp': timestamp,
                    'type': 'management',
                    'subtype': str(frame.subtype),
                    'strength': packet_signal,
                    'source_address': to_address(frame.mgmt.src),
                    'destination_address': to_address(frame.mgmt.dst),
                    'access_point_name': frame.ssid.data if hasattr(frame, 'ssid') else '(n/a)',
                    'access_point_address': to_address(frame.mgmt.bssid)
                }
                queue.put(record)
            elif frame.type == dpkt.ieee80211.CTL_TYPE:
                record = {
                    'timestamp': timestamp,
                    'type': 'control',
                    'subtype': str(frame.subtype),
                    'strength': packet_signal,
                    'source_address': '(n/a)', # not available in control packets
                    'destination_address': '(n/a)', # not available in control packets
                    'access_point_name': '(n/a)', # not available in control packets
                    'access_point_address': '(n/a)' # not available in control packets
                }
                queue.put(record)
            elif frame.type == dpkt.ieee80211.DATA_TYPE:
                record = {
                    'timestamp': timestamp,
                    'type': 'data',
                    'subtype': str(frame.subtype),
                    'strength': packet_signal,
                    'source_address': to_address(frame.data_frame.src),
                    'destination_address': to_address(frame.data_frame.dst),
                    'access_point_name': '(n/a)', # not available in data packets
                    'access_point_address': to_address(frame.data_frame.bssid) if hasattr(frame.data_frame, 'bssid') else '(n/a)'
                }
                queue.put(record)
        except Exception as e:
            logging.error(traceback.format_exc())
    packets.loop(-1, loop)

start()
