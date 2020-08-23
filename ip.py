import pyshark
import ipapi
import time
import pyfiglet
import pyperclip

interface = "wlo1"

pythonname = "Omegle  Location  Puller"
version = 0.1


ascii_banner = pyfiglet.figlet_format(pythonname + " " +  str(version))
print(ascii_banner)
print("By Alexander1022")
time.sleep(0.3)


cap = pyshark.LiveCapture(interface, bpf_filter="udp")
iplist = []
for packet in cap.sniff_continuously():
    if 'IP' in packet:
        ip = packet['IP'].src

        if ip.startswith("192.168"):
            stop = 1
        else:
            if ip not in iplist:
                iplist.append(ip)
                print("\n\n")
                print("IP: " + ipapi.location(ip, None, 'ip'))
                print("Country: " + ipapi.location(ip, None, 'country'))
                print("Region: " + ipapi.location(ip, None, 'region'))
                print("City: " + ipapi.location(ip, None, 'city'))
                time.sleep(0.3)
                print("------")
                time.sleep(0.1)
                time.sleep(3)
