#!/usr/bin/python3

# CHANGELOG
# 19SEP2021 - successfully converted this to python 3
#             left in the filter for "DeprecationWarning" just in case it is needed for the loop on or near line 301
#
# 19SEP2021 - adjusted channel list so that it scans on all bands (a,b, and g); this had to be adjusted
#             because some wi-fi channels can't be used by our listening interface
#
# TODO - fix lines 260, 261 so that exceptions are handled; sometimes signal strength doesn't make it and this needs to be accounted for
#
# Notes: dpkt might not handle certain conditions well; see this url for examples on how to handle exceptions:

import sys
import os
import logging
import traceback
import random
import subprocess
import time
import datetime
import multiprocessing
import queue
import sqlite3
import pcapy
import dpkt
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# mac
# interface = 'en0'
# monitor_enable  = 'tcpdump -i en0 -Ic1 -py IEEE802_11'
# monitor_disable = 'tcpdump -i en0 -Ic1'
# change_channel  = 'airport en0 channel {}'

# linux
interface = sys.argv[1]

INTERFACE_RETRIES_BEFORE_QUIT = 5
DEVICE_STARTUP_MONITOR_MODE_DELAY = 3

iw_dev = 'sudo iw dev'
monitor_enable  = ''.join(['sudo ip link set ', interface, ' down;sudo iw ', interface, ' set monitor control;sudo ip link set ', interface, ' up'])
monitor_disable  = ''.join(['sudo ip link set ', interface, ' down;sudo iw ', interface, ' set type managed;sudo ip link set ', interface, ' down'])
change_channel = ''.join(['sudo iw dev ', interface, ' set channel %s'])

#channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] # 2.4GHz only
#channels = [36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 149, 151, 153, 155, 157, 159, 161, 165] # 5Ghz only
channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165] # 2.4 and 5 Ghz 

# relies on parsing output from iwconfig to make sure that the specified interface is in monitor mode
def interface_monitor_mode_check():
    # TODO switch from iwconfig to iw; iwconfig is deprecated
    check_for_monitor_mode_for_interface = subprocess.check_output(''.join(['iwconfig ',interface,' | grep \'Mode:\' | awk -F \':\' \'{print $2}\' | awk \'{print $1}\'']), shell=True)
    #strip the newline character from the end
    check_for_monitor_mode_for_interface = check_for_monitor_mode_for_interface.rstrip().decode()
    if check_for_monitor_mode_for_interface != 'Monitor':
        print("Monitor mode is not enabled.")
        print("Increase the DEVICE_STARTUP_MONITOR_MODE_DELAY value and check the installed driver.")
        sys.exit()
    else:
        print("Monitor mode is enabled.  Check passed.")

def interface_existence_check():
        """ get the status code of "ip link show interface_name"
         a status code of zero indicates that it found the interface in the OS and executed cleanly """
        current_retries = 0
        check_for_status_zero_for_interface = os.system(''.join(['ip link show ', interface]))
        #print (str(check_for_status_zero_for_interface))
        if check_for_status_zero_for_interface == 0:
            print (interface + " interface exists")
            print ("Entering monitor mode...")
            return True
        else:
            print (interface + " doesn't exist.")
            print ("Check your setting for the wireless interface.")
            print ("If you updated any OS packages, don't forget to reload any custom wireless drivers.")
            
            if current_retries < INTERFACE_RETRIES_BEFORE_QUIT:
                current_retries += 1
                interface_existence_check()
                return False
            sys.exit()

def kill_interfering_services():
    # these are services that are stopped in Ubuntu/Debian
    # they have traditionally caused problems for any wireless interface in monitor mode
    subprocess.call("sudo systemctl stop wpa_supplicant", shell=True)
    subprocess.call("sudo systemctl stop avahi-daemon", shell=True)

def restore_interfering_services():
    # restore wpa_supplicant upon exit
    subprocess.call("sudo systemctl start wpa_supplicant", shell=True)
    subprocess.call("sudo systemctl start avahi-daemon", shell=True)

# do not rename this to queue or KeyboardInterrupt won't work correctly
q = multiprocessing.Queue()

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
    except KeyboardInterrupt: pass
    finally:
        stop_writing.set()
        stop_rotating.set()
        os.system(monitor_disable)

#def rotator(channels, change_channel):
#    def rotate(stop):
#        while not stop.is_set():
#            try:
#                # random channel selection
#                channel = str(random.choice(channels))
#                logging.info('Changing to channel ' + channel)
#                os.system(change_channel % channel)
#                time.sleep(1) # seconds
#            except KeyboardInterrupt: pass
#    stop = multiprocessing.Event()
#    multiprocessing.Process(target=rotate, args=[stop]).start()
#    return stop

def rotator(channels, change_channel):
    def rotate(stop):
        amount_of_channels = len(channels)
        print("Amount of channels defined: " + str(amount_of_channels))
        while not stop.is_set():
            try:
                for channel_index in range(0,amount_of_channels):
                    #print str(channels[channel_index])
                    channel = str(channels[channel_index])
                    if channel_index == len(channels):
                        channel_index = 0
                        #channel = str(random.choice(channels))
                    logging.info('Changing to channel ' + channel)
                    print("Changing to channel: " + str(channel))
                    os.system(change_channel % channel)
                    time.sleep(1) # seconds
            #except KeyboardInterrupt: pass
            except KeyboardInterrupt: sys.exit()
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
                for _ in range(0, q.qsize()):
                    item = q.get_nowait()
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
                    #cursor.execute(insert.decode('utf-8'), item)
                    cursor.execute(insert, item)
                db.commit()
                cursor.close()
                time.sleep(1) # seconds
            except queue.Empty: pass
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
    return ':'.join('%02x' % b for b in address)

def sniff(interface):
    interface_existence_check()
    kill_interfering_services()
    os.system(monitor_enable)
    time.sleep(DEVICE_STARTUP_MONITOR_MODE_DELAY) # Delay to wait for monitor mode
    # insert check here for confirmation of monitor mode
    interface_monitor_mode_check()
    os.system(iw_dev)

    max_packet_size = 256 # bytes
    promiscuous = 0 # boolean masquerading as an int
    timeout = 100 # milliseconds
    packets = pcapy.open_live(interface, max_packet_size, promiscuous, timeout)
    packets.setfilter('') # bpf syntax (empty string = everything)
    def loop(header, data):
        timestamp = datetime.datetime.now().isoformat()
        try:
            #try:
            packet = dpkt.radiotap.Radiotap(data)
            #except (KeyError, dpkt.UnpackError):
            #    pass
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
                q.put(record)
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
                q.put(record)
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
                q.put(record)
        except Exception as e:
            logging.error(traceback.format_exc())
    packets.loop(-1, loop)

start()
