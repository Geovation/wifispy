Wifi Spy
========

Sniff Wifi traffic, log device addresses.

Uses [Pcapy](https://github.com/CoreSecurity/pcapy) to capture packets. It's probably the best mantained out of [many](https://pypi.python.org/pypi?%3Aaction=search&term=pcap) libraries wrapping the somewhat definitive packet capture library [libpcap](https://github.com/the-tcpdump-group/libpcap).

Uses [Dpkt](https://github.com/kbandla/dpkt) to interrogate and extract data from each packet. It's one of two popular packet manipulation libraries, the other being [Impacket](https://github.com/CoreSecurity/impacket), which I had less luck with.


Running
-------

There's two different sets of configuration for Mac OS and Linux in `wifispy.py`, you'll have to comment out the appropriate set before running. I've only been able to make it work on Linux so far.

    $ pip install -r requirements.txt
    $ sudo python wifispy.py

Needs to be run with `sudo` because we're doing system-level stuff. For the same reason `pcapy` won't work within a virtual environment.


Approach
--------

1. Put card into [monitor mode](https://en.wikipedia.org/wiki/Monitor_mode). This means it will passively sniff all wireless traffic it sees. It differs from the somewhat similar [promiscuous mode](https://en.wikipedia.org/wiki/Promiscuous_mode), which (as I understand it) gives you more information, but requires you to be connected to a network. Not all cards support monitor mode. This is done via a terminal command, as it doesn't seem possible through Python.

2. Rotate channels. There are 13 channels in the 2.4GHz band, which are the most commonly used. There are also a number of others in the 5GHz range, but not all cards support these channels. Since cards can only be tuned to one channel at a time, we need to randomly switch channels in the background to ensure we're picking up devices using any channel. This is also done via a terminal command.

3. Sniff packets using Pcapy. Each packet recieved goes into a function for processing.

4. Process sniffed packets using Dpkt. Each first needs to be decoded. Using a [radiotap](http://www.radiotap.org/defined-fields) decoder means we can also pull out other interesting bits of information. There are three types of wireless (aka. 802.11) packet: management, control, and data. Each differs in what information it contains.

5. Extract the source Mac address from each management and data packet (control packets don't include this). If the address has already been seen, update the 'last seen' field to the current time. Otherwise, store the address and use the current time for both the 'first seen' and 'last seen' fields.

6. In the background, periodically write this list of Mac addresses and dates to a CSV file.


Other tools
-----------

* [wifi-monitor](https://github.com/dave5623/wifi_monitor)
* [wifi-rifle](https://github.com/sensepost/WiFi-Rifle)


Articles
--------

* https://www.crc.id.au/tracking-people-via-wifi-even-when-not-connected/
* http://edwardkeeble.com/2014/02/passive-wifi-tracking/


On the command-line
-------------------

This is a list of commands I've found useful whilst working on this project.

### Mac

You will need to use the `airport` command, so create a symlink:

    $ sudo ln -s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/local/bin/airport

Find out the names of your network interfaces:

    $ ifconfig

The default Wifi interface appears to be named `en0`.

Select the channel you would like to sniff (here, channel 6):

    $ airport channel 6

See all the existing networks and their channels:

    $ airport en0 scan

Put your card into monitor mode:

    $ sudo tcpdump -i en0 -Ic1 -py IEEE802_11

If this has worked it will say so in `airport en0 getinfo`.

To take the card out of monitor mode:

    $ sudo tcpdump -i en0 -Ic1

Sniff traffic and store in a `pcap` file:

    $ sudo tcpdump -i en0 -I -pw output.pcap

### Linux

Check what country the system thinks you're in. This will affect what channels you can use.

    $ iw reg get

It should say `country GB`, but if not:

    $ iw reg set GB

This will mean you get all possible UK frequencies when you:

    $ iwlist wlan1 freq

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
