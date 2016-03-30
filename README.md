Wifi Spy
========

An attempt to sniff Wifi traffic.

Uses [Pcapy](https://github.com/CoreSecurity/pcapy) to capture packets. It's probably the best mantained out of [many] (https://pypi.python.org/pypi?%3Aaction=search&term=pcap) libraries wrapping the somewhat definitive packet capture library [libpcap] (https://github.com/the-tcpdump-group/libpcap).

Uses [Impacket] (https://github.com/CoreSecurity/impacket) to interrogate and extract data from each packet. It's one of two popular packet manipulation libraries, the other being [dpkt] (https://github.com/kbandla/dpkt).


Running
-------

    $ pip install -r requirements.txt
    $ sudo python wifispy.py

Needs to be run with `sudo` because we're doing system-level stuff. For the same reason `pcapy` won't work within a virtual environment.


Problems
--------

We never seem to get any real packets coming through from `pcapy`. Suspect it's an issue with the card not being correctly put into monitor mode, but can't say for sure. Doing it from the command-line works as expected.


Other approaches
----------------

* Use [`pyshark`] (https://github.com/KimiNewt/pyshark), which wraps [Wireshark] (https://www.wireshark.org/)'s `tshark` command-line utility.
* Call `tcpdump` to write a `pcap` file in one thread, then read that file from within Python.


Other tools
-----------

* [wifi-monitor] (https://github.com/dave5623/wifi_monitor)
* [wifi-rifle] (https://github.com/sensepost/WiFi-Rifle)


Articles
--------

* https://www.crc.id.au/tracking-people-via-wifi-even-when-not-connected/
* http://edwardkeeble.com/2014/02/passive-wifi-tracking/


On the command-line
-------------------

### Mac

You will need to use the `airport` command, so create a symlink:

    $ sudo ln -s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/local/bin/airport

Find out the names of your network interfaces:

    $ ifconfig

The default Wifi interface appears to be named `en0`.

Select the channel you would like to sniff (here, channel 6):

    $ airport -c6

See all the existing networks and their channels:

    $ airport -s

Put your card into monitor mode:

    $ sudo tcpdump -i en0 -Ic1 -py IEEE802_11

If this has worked it will say so in `airport -I`.

To take the card out of monitor mode:

    $ sudo tcpdump -i en0 -Ic1

Sniff traffic and store in a `pcap` file:

    $ sudo tcpdump -i en0 -I -pw output.pcap

### Linux

Find out the names of your network interfaces:

    $ ifconfig

The default Wifi interface appears to be named `wlan1`.

Select the channel you would like to sniff (here, channel 6):

    $ iw dev wlan1 set channel 6

See all the existing networks and their channels:

    $ sudo iwlist wlan1 scan

Put your card into monitor mode:

    $ iw dev wlan1 set type monitor

If this has worked it will say so in `iwconfig`.

To take the card out of monitor mode:

    $ iw dev wlan1 set type managed

Sniff traffic and store in a `pcap` file:

    $ sudo tcpdump -i en0 -I -pw output.pcap