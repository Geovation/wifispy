import sys
import os
import logging
import traceback
import random
import time
import datetime
import multiprocessing
import Queue
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
change_channel  = 'iw dev wlan1mon set channel %s'

channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] # 2.4GHz only

queue = multiprocessing.Queue()

subtypes_management = {
    0: 'association-request',
    1: 'association-response',
    2: 'reassociation-request',
    3: 'reassociation-response',
    4: 'probe-request',
    5: 'probe-response',
    8: 'beacon',
    9: 'announcement-traffic-indication-message',
    10: 'disassociation',
    11: 'authentication',
    12: 'deauthentication',
    13: 'action'
}

subtypes_control = {
    8: 'block-acknowledgement-request',
    9: 'block-acknowledgement',
    10: 'power-save-poll',
    11: 'request-to-send',
    12: 'clear-to-send',
    13: 'acknowledgement',
    14: 'contention-free-end',
    15: 'contention-free-end-plus-acknowledgement'
}

subtypes_data = {
    0: 'data',
    1: 'data-and-contention-free-acknowledgement',
    2: 'data-and-contention-free-poll',
    3: 'data-and-contention-free-acknowledgement-plus-poll',
    4: 'null',
    5: 'contention-free-acknowledgement',
    6: 'contention-free-poll',
    7: 'contention-free-acknowledgement-plus-poll',
    8: 'qos-data',
    9: 'qos-data-plus-contention-free-acknowledgement',
    10: 'qos-data-plus-contention-free-poll',
    11: 'qos-data-plus-contention-free-acknowledgement-plus-poll',
    12: 'qos-null',
    14: 'qos-contention-free-poll-empty'
}

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
                channel = str(random.choice(channels))
                logging.info('Changing to channel ' + channel)
                os.system(change_channel % channel)
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
                    cursor.execute(insert.decode('utf-8'), item)
                db.commit()
                cursor.close()
                time.sleep(1) # seconds
            except Queue.Empty: pass
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
    cursor.execute(create.decode('utf-8'))
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
                    'subtype': subtypes_management[frame.subtype],
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
                    'subtype': subtypes_control[frame.subtype],
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
                    'subtype': subtypes_data[frame.subtype],
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
