#!/usr/bin/env python

import logging, sys, json, time, signal, httplib, urllib, unicodedata
from scapy.all import *
from netaddr import *

version = "0.3"

filename = "whoishere.conf"
logfilename = "whoishere.log"
maxlenght = 20
minute_list = []
list = []
uniquefingerprint = []

reload(sys)
sys.setdefaultencoding('utf-8')

def ConfigCheck():
	if not os.path.isfile(filename) :
		print "\n\033[91m\033[1m[+]\033[0m No configuration file found.\033[0m\n"
		file = open(filename, "w")
		file.write('{'\
		'"config" : [{"interface": "wlan0mon"},\n'\
		'            {"fingerprint_signal": false},\n'\
                '            {"fingerprint_minutes": false},\n'\
		'            {"pushoverapitoken": ""},\n'\
		'            {"pushoveruserkey": "" }],\n'\
		'"list"   : [{"name": "James Clerk Maxwell", "mac": "00:co:ca:c0:79:fa", "color": "1"},\n'\
		'            {"name": "Christian Hulsmeyer", "mac": "ba:ad:c0:de:88:ca", "color": "2"},\n'\
        	'	     {"name": "Heinrich Hertz", "mac": "e0:0f:00:0a:d0:a0", "color": "3"}]\n'\
		'}')
		file.close()
		print "\033[93m\033[1m[+]\033[0m Example configuration file created: \033[94m\033[1m[" + filename + "]\033[0m\n"
		print "\033[93m\033[1m[+]\033[0m Modify configuration file to add monitor interface and list of names and MACs.\n"
		print "\033[93m\033[1m[+]\033[0m Then run 'python whoishere.py'\033[0m\n"
		exit()
	else :
		try :
			with open(filename,'rU') as f: list.append(json.load(f))
			global interface
			interface = str(list[0]['config'][0]['interface'])
		except :
			print "\033[91mSomething is wrong with the configuration file."
			print "Edit or delete "+filename+" and try again.\033[0m\n\n"
			exit()
        global fingerprint_signal
        if list[0]['config'][1]['fingerprint_signal'] :
                fingerprint_signal = True
        else :
                fingerprint_signal = False
        global fingerprint_minutes
        if list[0]['config'][2]['fingerprint_minutes'] :
                fingerprint_minutes = True
        else :
                fingerprint_minutes = False
	global pushoverenabled
        if str(list[0]['config'][3]['pushoverapitoken']) != "" :
                pushoverenabled = "Enabled"
        else :
                pushoverenabled = "Disabled"
        


def Welcome() :
	banner = "\n".join([
        '\n        /         /      /                  ',
	'       (___  ___    ___ (___  ___  ___  ___ ',
	'  |   )|   )|   )| |___ |   )|___)|   )|___)',
	'  |/\/ |  / |__/ |  __/ |  / |__  |    |__  '])

        print banner
        print "\n           \033[1;33mWIFI Client Detection %s\033[0m" % version
        print ""
        print "  Author: Pedro Joaquin @_hkm (pjoaquin@websec.mx)"
        print "  To kill this script hit CRTL-C"
        print ""

def PrintConfig() :
	print "\n\033[92m\033[1m[+]\033[0m Current List:"
	print "    # :        MAC        -    NAME"
	for i in range(len(list[0]['list'])) :
		COLOR = '\033[9'+list[0]['list'][i]['color']+'m'
		print "    "+str(i)+" : " + COLOR + list[0]['list'][i]['mac']+ " - " + list[0]['list'][i]['name'] + '\033[0m'
        print "\n\033[92m\033[1m[+]\033[0m Configuration:"
	timea = time.strftime("%Y-%m-%d %H:%M") + "]\033[0m"
	print "    Current Time            \033[94m\033[1m[" + timea
        print "    Configuration File      \033[94m\033[1m[" + filename + "]\033[0m"
	print "    Log File                \033[94m\033[1m[" + logfilename + "]\033[0m"
	print "    Monitor Interface       \033[94m\033[1m[" + interface + "]\033[0m"
	print "    Fingerprint Signal      \033[94m\033[1m[" + ("Enabled" if fingerprint_signal else "Disabled") + "]\033[0m"
	print "    Fingerprint Minutes     \033[94m\033[1m[" + ("Enabled" if fingerprint_minutes else "Disabled") + "]\033[0m"
	print "    Pushover Notifications  \033[94m\033[1m[" + pushoverenabled + "]\033[0m\n"
	print "\n\033[92m\033[1m[+]\033[0m Listening for probe requests...\n"

def GetOUI(pkt) :
	global oui
	try :
		oui = OUI(pkt.addr2.replace(":","").upper()[0:6])
		oui = oui.registration().org
	except :
		oui = "(Unknown)"

def SearchList(pkt) :
	global COLOR
	global name
	name = "(Unknown)"
        COLOR = ""
	if pkt.info == "" : pkt.info = "(Hidden)"
	for i in range(len(list[0]['list'])) :
		if pkt.addr2 == list[0]['list'][i]['mac'] :
			name = list[0]['list'][i]['name']
			COLOR = '\033[9'+list[0]['list'][i]['color']+'m'

def PrintInfo(pkt) :
	global fingerprint
	global outputline
	timea = time.strftime("%Y-%m-%d %H:%M:%S")
	timefingerprint = time.strftime("%Y-%m-%d %H" + (":%M" if fingerprint_minutes else ""))
	namef = " NAME: " + name.ljust(maxlenght)[0:maxlenght]
	mac = " MAC: " + pkt.addr2
	SSID = " SSID: " + pkt.info.ljust(maxlenght)[0:maxlenght]
	OUI = " OUI: "+ oui
	db = -(256-(ord(pkt.notdecoded[-4:-3]) if pkt.notdecoded[-4:-3] else 0))
        if db <= -100:
                quality = 0
        elif db >= -50:
                quality = 100
        else:
                quality = 2 * (db + 100)
        quality = str(quality)+"%"
        quality = " SIGNAL: " + quality.ljust(4, ' ')
        fingerprint = COLOR + timefingerprint + (quality if fingerprint_signal else "") + namef + mac + SSID + OUI +'\033[0m'
        outputline = COLOR + timea + quality + namef + mac + SSID + OUI +'\033[0m'
	if fingerprint not in uniquefingerprint :
		uniquefingerprint.append(fingerprint)
        	print outputline
		if COLOR == '\033[9'+'1'+'m' :
                        try :
                                pushover_notification(outputline[22:-3])
                        except :
                                print "Failed to send pushover notification: " + outputline[22:-3]

def WriteLog(outputline):
        file = open(logfilename, "a")
        file.write(outputline + "\n")
        file.close()


def PacketHandler(pkt) :
        if pkt.haslayer(Dot11ProbeReq) :
        	GetOUI(pkt)
		SearchList(pkt)
		PrintInfo(pkt)
		WriteLog(outputline)

def signal_handler(signal, frame):
        print "\n\033[92m\033[1m[+]\033[0m Exiting...\n"
        sys.exit(0)

def pushover_notification(fingerprint):
	conn = httplib.HTTPSConnection("api.pushover.net:443")
	conn.request("POST", "/1/messages.json",
  	urllib.urlencode({
	"token": str(list[0]['config'][3]['pushoverapitoken']),
	"user": str(list[0]['config'][4]['pushoveruserkey']),
    	"message": fingerprint,
  	}), { "Content-type": "application/x-www-form-urlencoded" })
	conn.getresponse()


Welcome()
ConfigCheck()
PrintConfig()
signal.signal(signal.SIGINT, signal_handler)
sniff(iface=interface, prn = PacketHandler, store=0)
signal.pause()
