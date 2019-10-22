# -*- coding: utf-8 -*-
import argparse
import os
import sys
import datetime
import time
import dateutil
import socket
import zlib
from base64 import b64decode
import dateutil.parser
import dns.resolver
from print_msg import *

def domain_check(domain):
    Domain = domain.replace("https://", "").replace("http://", "")
    Domain = Domain.split("/")[0]
    try:
        my_resolver = dns.resolver.Resolver()
        my_resolver.nameservers = ['8.8.8.8']
        answers = my_resolver.query(Domain, 'A')

        printh(
            "%s IP addresses returned, using first A record %s for %s." % (len(answers), answers[0], Domain))
        IPaddr = str(answers[0])

    except dns.resolver.NXDOMAIN:
        printe("No A records returned from public DNS %s." %
               my_resolver.nameservers, "Domain resolve / Public")
    try:
        IPaddrLocal = socket.gethostbyname(Domain)
        if IPaddrLocal != IPaddr:
            printh(
                "Public DNS reports different results (%s) from host DNS results (%s)" %
                (IPaddr, IPaddrLocal))
    except socket.gaierror:
        printe(
            "Resolving domain %s failed." %
            Domain, "Domain resolve / Local")
        IPaddr = ""

    return IPaddr,Domain

class Setup :
    arg = None
    missingkeys = []
    def __init__(self):
        splash = '''
██╗██████╗ ██╗███╗   ██╗████████╗
██║██╔══██╗██║████╗  ██║╚══██╔══╝
██║██████╔╝██║██╔██╗ ██║   ██║   
██║██╔═══╝ ██║██║╚██╗██║   ██║   
██║██║     ██║██║ ╚████║   ██║   
╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝   ╚═╝                             
          '''
        print splash
        self.args_setup()
        # Specify resources and API keys
        self.ownPath = os.path.dirname(sys.argv[0]) + "/"
        if self.ownPath is "/" or self.ownPath is "":
            self.ownPath = "./"
        self.current_date = str(datetime.datetime.now().strftime("%Y-%m-%d-%H:%M"))
        self.eNow = int(time.mktime(dateutil.parser.parse(self.current_date).timetuple()))
        self.targetPortscan = [80, 443, 8000, 20, 21, 22, 23, 25, 53]  # What ports to scan
        self.blacklistSourceFile = self.ownPath + "blacklists.txt"
        self.sourceListSpamDNS = [
            "zen.spamhaus.org",
            "spam.abuse.ch",
            "cbl.abuseat.org",
            "virbl.dnsbl.bit.nl",
            "dnsbl.inps.de",
            "ix.dnsbl.manitu.net",
            "dnsbl.sorbs.net",
            "bl.spamcannibal.org",
            "bl.spamcop.net",
            "xbl.spamhaus.org",
            "pbl.spamhaus.org",
            "dnsbl-1.uceprotect.net",
            "dnsbl-2.uceprotect.net",
            "dnsbl-3.uceprotect.net",
            "db.wpbl.info"
        ]

    def config_file_check(self):
        # Read or create configuration file

        if os.path.isfile(self.ownPath + "apikeys.conf"):
            settings = {}
            with open(self.ownPath + "apikeys.conf", "r+") as f:
                for line in f:
                    if line[0] == "#":
                        continue
                    if ":" in line:
                        (key, val) = line.split(":")
                        settings[key.strip()] = val.strip()
                f.close()
            if settings['WebOfTrustAPIKey'] is "":
                self.missingkeys.append("Web Of Trust")
                self.arg.weboftrust = False
            if settings['VirusTotalAPIKey'] is "":
                self.missingkeys.append("VirusTotal")
                self.arg.virustotal = False
            if settings['MetaScanAPIKey'] is "":
                self.missingkeys.append("MetaScan")
                self.arg.metascan = False
            if settings['ApiVoid'] is "":
                self.missingkeys.append("ApiVoid")
                self.arg.googlesafebrowsing = False
            if settings['TwitterConsumerKey'] is "" \
                    or settings['TwitterConsumerSecret'] is "" \
                    or settings['TwitterAccessToken'] is "" \
                    or settings['TwitterAccessTokenSecret'] is "":
                self.missingkeys.append("Twitter")
                self.arg.twitter = False
        else:  # If no configuration file present, create one.
            printe("No API key configuration file found, writing a template to %sapikeys.conf." % self.ownPath,
                   "Configuration")
            f = open(self.ownPath + "apikeys.conf", "w")
            f.write('''WebOfTrustAPIKey: 
VirusTotalAPIKey: 
MetaScanAPIKey:
TwitterConsumerKey: 
TwitterConsumerSecret: 
TwitterAccessToken: 
TwitterAccessTokenSecret: 
ApiVoid: ''')
            settings = {
                'WebOfTrustAPIKey': None,
                'VirusTotalAPIKey': None,
                'ApiVoid': None,
                'MetaScanAPIKey': None,
                'TwitterConsumerKey': None,
                'TwitterConsumerSecret': None,
                'TwitterAccessToken': None,
                'TwitterAccessTokenSecret': None,
            }
            self.arg.twitter = self.arg.passivetotal = self.arg.weboftrust = self.arg.virustotal = self.arg.metascan = self.arg.apivoid = False
            f.close()
        return settings

    def validate_ip(self,ip):  # Validate IP address format
        try:
            socket.inet_aton(ip)
        except Exception:
            return False
        return True

    def args_setup(self):
        parser = argparse.ArgumentParser(description='Get actions')

        parser.add_argument("-il",
                            "--IPlist",
                            metavar='IP list',
                            type=str,
                            help="List of IPs")
        parser.add_argument("-dl",
                            "--Domainlist",
                            metavar='Domain list',
                            type=str,
                            help="List of Domains")
        parser.add_argument("-d",
                            "--domain",
                            metavar='domain name',
                            type=str,
                            help="Target domain name")
        parser.add_argument("-i",
                            "--ip",
                            metavar='IP address',
                            type=str,
                            help="Target IP address")
        parser.add_argument("-a",
                            "--all",
                            help="run all queries",
                            action="store_true")
        parser.add_argument("-l",
                            "--lists",
                            help="run all third-party lists for matches",
                            action="store_true")
        parser.add_argument("-p",
                            "--probes",
                            help="run all host-contacting probes",
                            action="store_true")
        parser.add_argument("-pg",
                            "--ping",
                            help="Ping address",
                            action="store_true")
        parser.add_argument("-ws",
                            "--whois",
                            help="Query WHOIS information",
                            action="store_true")
        parser.add_argument("-cr",
                            "--cert",
                            help="Display certificate information via OpenSSL",
                            action="store_true")
        parser.add_argument("-sp",
                            "--scanports",
                            help="Scan common ports",
                            action="store_true")
        parser.add_argument("-sh",
                            "--scanheaders",
                            help="Scan common ports and try to retrieve headers",
                            action="store_true")
        parser.add_argument("-ms",
                            "--metascan",
                            help="Query Metscan Online for detections",
                            action="store_true")
        parser.add_argument("-wt",
                            "--weboftrust",
                            help="Query Web Of Trust reputation database",
                            action="store_true")
        parser.add_argument("-sl",
                            "--spamlists",
                            help="Check a number of spam resolvers for IP",
                            action="store_true")
        parser.add_argument("-bl",
                            "--blacklists",
                            help="Check local and third-party blacklists for matches",
                            action="store_true")
        parser.add_argument("-vt",
                            "--virustotal",
                            help="Query passive DNS and detection records from VirusTotal",
                            action="store_true")
        parser.add_argument("-otx",
                            "--otx",
                            help="Query OTX analysis data",
                            action="store_true")
        parser.add_argument("-pv",
                            "--apivoid",
                            help="Searching with api void",
                            action="store_true")
        parser.add_argument("-tw",
                            "--twitter",
                            help="Search Twitter for recent mentions of Domain or IP",
                            action="store_true")

        parser.add_argument("-nt",
                            "--note",
                            metavar='note',
                            type=str,
                            help="Add a note to the output, \
        this could be a project name or description of address.")
        parser.add_argument("-O",
                            "--openlink",
                            help="Open GeoIP location in Google Maps",
                            action="store_true")


        parser.add_argument("-NG", "--nogfx",
                            help="Suppress line graphics",
                            action="store_true")
        parser.add_argument("-S", "--nosplash",
                            help="Suppress cool ASCII header graphic",
                            action="store_true")
        parser.add_argument("-P", "--pause",
                            help="Pause between modules",
                            action="store_true")
        self.arg = parser.parse_args()

        if self.arg.lists is True or self.arg.all is True:
            self.arg.googlesafebrowsing = True
            self.arg.weboftrust = True
            self.arg.virustotal = True
            self.arg.blacklists = True
            self.arg.spamlists = True
            self.arg.twitter = True
            self.arg.metascan = True

        if self.arg.probes is True or self.arg.all is True:
            self.arg.cert = True
            self.arg.ping = True
            self.arg.scanheaders = True
            self.arg.scanports = True

        if self.arg.all is True:
            self.arg.whois = True

        return self.arg
