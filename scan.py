from TwitterSearch import *
import os
import requests
import json
import sys
import dns.resolver
import subprocess
import socket
import random
import time
import dateutil
import hashlib
import zipfile
import StringIO
import gzip
import operator
import datetime
from OTXv2 import OTXv2
import IndicatorTypes

from print_msg import *

class Scan:
    
    def __init__(self,IP,Domain,Settings,arg):
        self.IPaddr = IP
        self.Domain = Domain
        self.settings = Settings
        self.arg = arg
        self.ownPath = os.path.dirname(sys.argv[0]) + "/"
        if self.ownPath is "/" or self.ownPath is "":
            self.ownPath = "./"
        self.curDate = str(datetime.datetime.now().strftime("%Y-%m-%d-%H:%M"))
        self.eNow = int(time.mktime(dateutil.parser.parse(self.curDate).timetuple()))

        if IP :printh('*** Scanning {} ***'.format(IP))
        else: printh('*** Scanning {} ***'.format(Domain))
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

        self.targetPortscan = [80, 443, 8000, 20, 21, 22, 23, 25, 53]  # What ports to scan
        self.uapool = [
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',
            'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko',
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 7.0; InfoPath.3; .NET c 3.1.40767; Trident/6.0; en-IN)',
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
            'Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)',
            'Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)',
            'Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)',
            'Mozilla/1.22 (compatible; MSIE 10.0; Windows 3.1)',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1',
            'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A'
        ]
        self.headers = {'user-agent': 'Mozilla/5.0 (Check.py extended address information lookup tool)',
                   'referer': 'https://www.github.com/AnttiKurittu/check'}

    def matchfinder(self,f):
        if self.IPaddr != "":
            iIPr = self.IPaddr.split(".")
            iIPr = iIPr[0] + "." + iIPr[1] + "." + iIPr[2] + ".0"
        else:
            iIPr = ""
        out = []
        dm = ipm = rm = False
        for line in f:
            if self.Domain != "" and self.Domain in line:
                dm = True
                out.append(
                    c.Y + "Domain match! " + c.END + line.replace(self.Domain, c.R + self.Domain + c.END).replace("\n", ""))
            if self.IPaddr != "" and self.IPaddr in line:
                ipm = True
                out.append(
                    c.Y + "IP match! " + c.END + line.replace(self.IPaddr, c.R + self.IPaddr + c.END).replace("\n", ""))
            if iIPr != "" and iIPr in line:
                ipm = True
                out.append(
                    c.Y + "Range match! " + c.END + line.replace(iIPr, c.R + iIPr + c.END).replace("\n", ""))
        if dm == False and ipm == True and self.Domain != "":
            out.append(g.PIPE + "Domain name not found." + c.END)
        elif ipm == False and dm == True:
            out.append("IP address not found." + c.END)
        else:
            out.append("Address " + c.G + "not found" + c.END + " in list." + c.END)
        return out

    def scan_all(self):
        self.ping_scan()
        self.whois()
        self.virus_total()
        self.otx_scan()
        self.api_void()
        self.twitter_scan()
        self.meta_scan()
        self.web_of_trust()
        self.black_list()
        self.spam_list()
        self.scan_ports()
        self.openssl()

    def twitter_scan(self):
        if self.arg.twitter:
            try:
                tso = TwitterSearchOrder()  # create a TwitterSearchOrder object
                keyword_domain = "\"" + self.Domain + "\""
                keyword_ip = "\"" + self.IPaddr + "\""
                if self.Domain == "" and self.IPaddr != "":
                    tso.set_keywords([keyword_ip], or_operator=True)
                    keywords_desc = "IP address"
                elif self.Domain != "" and self.IPaddr == "":
                    tso.set_keywords([keyword_domain], or_operator=True)
                    keywords_desc = "domain name"
                else:
                    tso.set_keywords([keyword_domain, keyword_ip], or_operator=True)
                    keywords_desc = "IP address or domain name"

                printh("Querying Twitter for tweets mentioning %s..." % keywords_desc)
                # tso.set_language('en')
                tso.set_include_entities(False)
                tso.remove_all_filters()
                ts = TwitterSearch(
                    consumer_key=self.settings['TwitterConsumerKey'],
                    consumer_secret=self.settings['TwitterConsumerSecret'],
                    access_token=self.settings['TwitterAccessToken'],
                    access_token_secret=self.settings['TwitterAccessTokenSecret']
                )
                i = 0
                for tweet in ts.search_tweets_iterable(tso):
                    if i < 100:
                        printl("[%s%s%s] %s@%s%s%s%s:" % (c.Y, tweet['created_at'], c.END, c.G, c.END,
                                                          c.BOLD, tweet['user']['screen_name'], c.END
                                                          ))
                        printl("%s" % (tweet['text'].encode('utf8').replace("\n", "%s/%s " % (c.R, c.END))))
                        try:
                            printl("\t%s=> Expanded URL:%s %s" % (
                            c.G, c.END, tweet['user']['entities']['url']['urls'][0]['expanded_url'].encode('utf8')
                            .replace(self.Domain, c.R + self.Domain + c.END).replace(self.IPaddr, c.R + self.Domain + c.END)))
                        except KeyError:
                            ()
                        except AttributeError:
                            ()
                        except IndexError:
                            ()  # Do nothing.
                        i += 1
                    else:
                        print(("Showing %s/100 results." % ts.get_amount_of_tweets()))
                        break
                if i == 0:
                    print("No tweets found.")
            except TwitterSearchException as e:
                print(e)

    def otx_scan(self):
        if self.arg.otx:
            try:
                printh('Quering OTX data ....')
                otx = OTXv2('b2ffda0576d05368171a92f08dc2c747f7dc0671b18a97f09e6c916fa5d618ca')
                try:os.mkdir('OTX output')
                except:pass
                path = os.path.dirname(__file__)

                if self.IPaddr:
                    out = otx.get_indicator_details_full(IndicatorTypes.IPv4,self.IPaddr)
                    ofile = 'OTX output/OTX - ' + self.IPaddr
                if self.Domain:
                    out = otx.get_indicator_details_full(IndicatorTypes.DOMAIN,self.IPaddr)
                    ofile = 'OTX output/OTX - ' + self.Domain

                file_path = os.path.join(path, ofile)
                out_file = open(file_path,'w')
                for key,value in out.iteritems():
                    out_file.write(unicode(key)+'\n')
                    out_file.write(unicode(value)+'\n')
                out_file.close()
                try:
                    printl('Pulses Count : {}'.format(out['general']['pulse_info']['count']), c.G)
                except:
                    printl('Pulses Count : 0', c.G)

                try:
                    printl('Malwares Count : {}'.format(out['malware']['count']),c.G)
                except:
                    printl('Malwares Count : 0', c.G)
                try:
                    printl('passive_dns Size  : {}'.format(len(out['passive_dns']['passive_dns'])),c.G)
                except:
                    printl('passive_dns Size  : 0', c.G)
                try:
                    printl('URL list Size  : {}'.format(out['url_list']['actual_size']),c.G)
                except:
                    printl('URL list Size  : 0', c.G)

                printl('OTX results stored on file {}'.format(ofile),c.G)
            except Exception as ex:
                printl('Error with otx_scan function : {}'.format(ex),c.R)

    def api_void(self):
        if self.arg.apivoid:
            try:
                printp('Scanning with APIVoid ... ')
                if self.Domain:
                    reply = requests.get('https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={}&host={}'.format(self.settings['ApiVoid'],self.Domain))
                else:
                    reply = requests.get('https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={}&ip={}'.format(self.settings['ApiVoid'],self.IPaddr))

                data = json.loads(reply.text)['data']['report']['blacklists']

                printl('Detection rate : {}'.format(data['detection_rate']),c.G)
                printl('Engines count  : {}'.format(data['engines_count']),c.G)
                for eng in data['engines'].values():
                    printl(str(eng),c.G)
            except Exception as ex:
                printl('Error with api_void function : {}'.format(ex),c.R)

    def ping_scan(self):
        if self.arg.ping:
            try:
                printh("Pinging %s, skip with CTRL-C..." % self.IPaddr)
                try:
                    response = os.system("ping -c 1 " + self.IPaddr + " > /dev/null 2>&1")
                    if response == 0:
                        printl("%s is responding to ping." % (self.IPaddr), c.G)
                    else:
                        printl("%s is not responding to ping." % (self.IPaddr), c.Y)
                except KeyboardInterrupt:
                    printl("Skipping ping.", c.R)
            except Exception as ex:
                printe("ping error: {}".format(ex),c.R)

    def meta_scan(self):
        if self.arg.metascan:
            try:
                postdata_desc = postdata = ""
                headers = {'apikey': self.settings['MetaScanAPIKey']}
                if self.Domain == "":
                    postdata = str({'address': [self.IPaddr]}).replace(" ", "").replace("\'", "\"")
                    postdata_desc = "IP address"
                if self.IPaddr == "":
                    postdata = str({'address': [self.Domain]}).replace(" ", "").replace("\'", "\"")
                    postdata_desc = "Domain name"
                if self.Domain != "" and self.IPaddr != "":
                    postdata = str({'address': [self.IPaddr, self.Domain]}).replace(" ", "").replace("\'", "\"")
                    postdata_desc = "IP address and domain name"
                printh("Querying Metascan Online with %s." % postdata_desc)
                reply = requests.post(
                    "https://ipscan.metadefender.com/v1/scan", data=postdata, headers=headers)

                if reply.status_code != 200:
                    if reply.status_code == 400:
                        printe("Error %s: Bad request." % (reply.status_code), "MetaScan")
                    elif reply.status_code == 403:
                        printe("Error %s: Lookup rate limit reached, try again later." % (reply.status_code), "MetaScan")
                    elif reply.status_code == 401:
                        printe("Error %s: Invalid API key." % (reply.status_code), "MetaScan")
                    elif reply.status_code == 503:
                        printe("Error %s: Internal server error, service temporarily unavailable." % (reply.status_code),
                               "MetaScan")
                    else:
                        printe("Error %s: Headers: %s Content: %s" % (reply.status_code, reply.headers, reply.content),
                               "MetaScan")
                else:
                    if str(reply.content) == "[]":
                        printp("Address not found in dataset.")
                    else:
                        replies = json.loads(reply.content)
                        for reply_dict in replies:
                            printp("%s%s%s: \t%s detections, scanned at %s" % (
                            c.BOLD, reply_dict['address'], c.END, reply_dict['detected_by'], reply_dict['start_time']))
                            printl("Geolocation: %s: %s (lat. %s, lon. %s)" % (reply_dict['geo_info']['country_code'],
                                                                               reply_dict['geo_info']['country_name'],
                                                                               reply_dict['geo_info']['latitude'],
                                                                               reply_dict['geo_info']['longitude']))
                            for i in reply_dict['scan_results']:
                                source = i['source']
                                for s in i['results']:
                                    if s['result'] != "unknown":
                                        printp("%s:" % source)
                                        printl("Detection time: %s\tUpdate time:%s\tConfidence: %s" % (
                                        s['detecttime'], s['updatetime'], s['confident']))
                                        printl("Result: %s%s%s \tAssessment: %s%s%s" % (
                                        c.Y, s['result'], c.END, c.Y, s['assessment'], c.END))
                                        printl("Alternative ID: %s" % s['alternativeid'])
            except Exception as ex:
                printe("Meta scan Error : {}".format(ex),c.R)

    def web_of_trust(self):
        if self.arg.weboftrust:
            try:
                printh("Querying Web Of Trust reputation API with domain name")
                target = 'http://' + self.Domain + '/'
                parameters = {'hosts': self.Domain + "/", 'key': self.settings['WebOfTrustAPIKey']}
                reply = requests.get(
                    "http://api.mywot.com/0.4/public_link_json2",
                    params=parameters,
                    headers=self.headers)
                reply_dict = json.loads(reply.text)
                categories = {
                    '101': c.R + 'Negative: Malware or viruses' + c.END,
                    '102': c.R + 'Negative: Poor customer experience' + c.END,
                    '103': c.R + 'Negative: Phishing' + c.END,
                    '104': c.R + 'Negative: Scam' + c.END,
                    '105': c.R + 'Negative: Potentially illegal' + c.END,
                    '201': c.Y + 'Questionable: Misleading claims or unethical' + c.END,
                    '202': c.Y + 'Questionable: Privacy risks' + c.END,
                    '203': c.Y + 'Questionable: Suspicious' + c.END,
                    '204': c.Y + 'Questionable: Hate, discrimination' + c.END,
                    '205': c.Y + 'Questionable: Spam' + c.END,
                    '206': c.Y + 'Questionable: Potentially unwanted programs' + c.END,
                    '207': c.Y + 'Questionable: Ads / pop-ups' + c.END,
                    '301': c.G + 'Neutral: Online tracking' + c.END,
                    '302': c.G + 'Neutral: Alternative or controversial medicine' + c.END,
                    '303': c.G + 'Neutral: Opinions, religion, politics ' + c.END,
                    '304': c.G + 'Neutral: Other ' + c.END,
                    '401': c.Y + 'Child safety: Adult content' + c.END,
                    '402': c.Y + 'Child safety: Incindental nudity' + c.END,
                    '403': c.R + 'Child safety: Gruesome or shocking' + c.END,
                    '404': c.G + 'Child safety: Site for kids' + c.END,
                    '501': c.G + 'Positive: Good site' + c.END}
                if reply.status_code == 200:
                    hasKeys = False
                    for key, value in reply_dict[self.Domain].iteritems():
                        if key == "target":
                            printp(
                                "Server response OK, Web Of Trust Reputation Score for %s%s%s:" %
                                (c.BOLD, value, c.END))
                        elif key == "1":
                            ()  # Deprecated
                        elif key == "2":
                            ()  # Deprecated
                        elif key == "0" or key == "4":
                            hasKeys = True
                            if int(value[0]) >= 0:
                                assessment = c.R + "Very poor" + c.END
                            if int(value[0]) >= 20:
                                assessment = c.R + "Poor" + c.END
                            if int(value[0]) >= 40:
                                assessment = c.Y + "Unsatisfactory" + c.END
                            if int(value[0]) >= 60:
                                assessment = c.G + "Good" + c.END
                            if int(value[0]) >= 80:
                                assessment = c.G + "Excellent" + c.END
                            if key == "0":
                                pipe()
                                printl("Trustworthiness:\t %s (%s) \t[%s%% confidence]" % (value[0], assessment, value[1]))
                            elif key == "4":
                                printl("Child safety:\t %s (%s) \t[%s%% confidence]" % (value[0], assessment, value[1]))
                        elif key == "categories":
                            pipe()
                            hasKeys = True
                            for e, s in value.iteritems():
                                printl("Category:\t %s \t[%s%% confidence]" % (categories[e], s))
                            pipe()
                        elif key == "blacklists":
                            hasKeys = True
                            for e, s in value.iteritems():
                                printl("Blacklisted:\t %s \tID: %s" % (e, s))
                        else:
                            printe("Unknown key %s => %s" % (key, value), "Web Of Trust")
                if hasKeys == False:
                    printl("Web Of Trust has no records for %s" % (self.Domain), c.G)
                    pipe()
                if reply.status_code != 200:
                    printe(
                        "Server returned status code %s see https://www.mywot.com/wiki/API for details." %
                        reply.status_code, "Web Of Trust")
            except KeyError:
                printe("Web Of Trust API key not present.", "Web Of Trust")

    def virus_total(self):
        if self.arg.virustotal:
            try:
                printh("Querying VirusTotal for %s..." % self.IPaddr)
                if self.IPaddr != "":
                    parameters_ip = {
                        'ip': self.IPaddr,
                        'apikey': self.settings['VirusTotalAPIKey']
                    }
                    vtresponse_ip = requests.get(
                        'https://www.virustotal.com/vtapi/v2/ip-address/report',
                        params=parameters_ip).content
                    vtresponse_dict = json.loads(vtresponse_ip)
                    if vtresponse_dict['response_code'] == 0:
                        printp("VirusTotal response: IP address not in dataset.")
                    else:
                        printp("VirusTotal response code %s: %s" % (
                        vtresponse_dict['response_code'], vtresponse_dict['verbose_msg']))
                        for entry in vtresponse_dict['resolutions']:
                            printl("%s Last resolved: %s" % (entry['hostname'], entry['last_resolved']))
                        pipe()
                        if len(vtresponse_dict['detected_urls']) >= 1:
                            printl("Detections in this IP address:", c.Y)
                            for entry in vtresponse_dict['detected_urls']:
                                if len(entry['url']) <= 80:
                                    printl(entry['url'].replace("http", "hxxp"))
                                else:
                                    printl(entry['url'][0:90] + c.Y + "...".replace("http", "hxxp"))
                                if entry['positives'] >= 1:
                                    printl("Positives: %s%s%s\tTotal:%s\tScan date:%s" % (
                                    c.R, entry['positives'], c.END, entry['total'], entry['scan_date']))
                                else:
                                    printl("Positives: %s\tTotal:%s\tScan date:%s" % (
                                    entry['positives'], entry['total'], entry['scan_date']))

                if self.Domain != "":
                    parameters_domain = {
                        'domain': self.Domain,
                        'apikey': self.settings['VirusTotalAPIKey']
                    }
                    vtresponse_domain = requests.get(
                        'https://www.virustotal.com/vtapi/v2/domain/report',
                        params=parameters_domain).content
                    vtresponse_dict = json.loads(vtresponse_domain)
                    if vtresponse_dict['response_code'] == 0:
                        printp("VirusTotal response: IP address not in dataset.")
                    else:
                        printp("VirusTotal response code %s: %s" % (
                        vtresponse_dict['response_code'], vtresponse_dict['verbose_msg']))
                        for entry in vtresponse_dict['resolutions']:
                            printl("%s Last resolved: %s" % (entry['ip_address'], entry['last_resolved']))
                        pipe()
                        if len(vtresponse_dict['detected_urls']) >= 1:
                            printl("Detections in this IP address:", c.Y)
                            for entry in vtresponse_dict['detected_urls']:
                                if len(entry['url']) <= 80:
                                    printl(entry['url'].replace("http", "hxxp"))
                                else:
                                    printl(entry['url'][0:90] + c.Y + "...".replace("http", "hxxp"))
                                if entry['positives'] >= 1:
                                    printl("Positives: %s%s%s\tTotal:%s\tScan date:%s" % (
                                    c.R, entry['positives'], c.END, entry['total'], entry['scan_date']))
                                else:
                                    printl("Positives: %s\tTotal:%s\tScan date:%s" % (
                                    entry['positives'], entry['total'], entry['scan_date']))
            except Exception as ex:
                printe("Error on virus total {}".format(ex),c.R)

    def black_list(self):
        if self.arg.blacklists:
            try:
                blacklistSourceFile = self.ownPath + "blacklists.txt"
                sourceCount = 0
                matchcollector = []
                totalLines = 0
                if os.path.isfile(blacklistSourceFile):
                    with open(blacklistSourceFile) as sourcefile:
                        blacklists = sourcefile.readlines()
                        sourceCount = 0
                else:
                    printe(
                        "No blacklist file found at %s" %
                        blacklistSourceFile,
                        "blacklist")
                    blacklists = ""
                for line in blacklists:
                    if line[:1] == "#":
                        continue
                    else:
                        sourceCount += 1

                printh("Searching local blacklists...")
                localfiles = os.listdir(self.ownPath + "localdata")
                for file in localfiles:
                    if file[0] == ".":
                        continue
                    domainmatch = ipmatch = rangematch = False
                    printp("Processing local blacklist file %s%s%s" % (c.BOLD, file, c.END))
                    file = self.ownPath + "localdata/" + file
                    file = open(file, "r+")
                    output = self.matchfinder(file.read().splitlines())
                    for line in output:
                        printl(line)

                printh("Downloading and searching from remote blacklists...")
                i = 0
                cacherefreshcount = 0
                for sourceline in blacklists:
                    sourceline = sourceline.split("|")
                    sourceurl = sourceline[0].replace("\n", "").replace(" ^", "")
                    if sourceurl[:1] == "#":
                        continue  # Skip comment lines
                    try:
                        sourcename = sourceline[1].replace("\n", "")
                    except IndexError:
                        # If no name specified use URL.
                        sourcename = sourceline[0].replace("\n", "")
                    i += 1
                    listfile = ""
                    linecount = 0
                    domainmatch = False
                    ipmatch = False
                    printp(
                        "Downloading from %s%s%s [%s of %s sources]:" %
                        (c.BOLD, sourcename, c.END, i, sourceCount))
                    try:
                        data = ""
                        head = requests.head(sourceurl, headers=self.headers)
                    except Exception:
                        printe("[%sFail!%s] Unable to connect to %s" % (c.R, c.END, sourcename), "blacklists")
                        continue
                    try:
                        timestamp = head.headers['Last-Modified']
                    except KeyError:
                        timestamp = "1970-01-02 00:00:00"
                    eStamp = int(time.mktime(dateutil.parser.parse(timestamp).timetuple()))

                    cacherefreshcount += 1
                    req = requests.get(sourceurl, stream=True, headers=self.headers)
                    try:
                        cd = req.headers['Content-Disposition']
                    except Exception:
                        cd = ""
                    filesize = req.headers.get('content-length')
                    if not filesize:
                        # Assuming no content-length header or content-type
                        sys.stdout.write(
                            g.PIPE +
                            "[" +
                            c.G +
                            "Done!" +
                            c.END +
                            "] Content-length not received. " +
                            cd +
                            c.END)
                        data = req.content
                        cType = "text/plain"
                    else:
                        cType = req.headers.get('content-type')
                        if not cType:
                            cType = "text/plain"
                        sys.stdout.write(g.PIPE +
                                         "[" +
                                         c.R +
                                         "     " +
                                         c.END +
                                         "] Filesize: " +
                                         str(int(filesize) /
                                             1024) +
                                         " kb \tContent type: " +
                                         str(cType) +
                                         " \r" +
                                         g.PIPE +
                                         "[")
                        part = int(filesize) / 5
                        count = 0
                        for chunk in req.iter_content(part):
                            count += 1
                            if count <= 5:
                                if count == 1:
                                    sys.stdout.write(c.G + "D" + c.END)
                                if count == 2:
                                    sys.stdout.write(c.G + "o" + c.END)
                                if count == 3:
                                    sys.stdout.write(c.G + "n" + c.END)
                                if count == 4:
                                    sys.stdout.write(c.G + "e" + c.END)
                                if count == 5:
                                    sys.stdout.write(c.G + "!" + c.END)
                                sys.stdout.flush()
                            data = data + chunk
                        while count < 5:  # Fill the meter if the chunks round down.
                            count += 1
                            sys.stdout.write(c.G + "!" + c.END)
                            sys.stdout.flush()
                    if "application/zip" in cType:
                        filelist = {}
                        zip_file_object = zipfile.ZipFile(StringIO.StringIO(data))
                        for info in zip_file_object.infolist(
                        ):  # Get zip contents and put to a list
                            # Add files to a list
                            filelist[info.filename] = info.file_size
                        # Sort list by value; largest file is last
                        sortedlist = sorted(
                            filelist.items(), key=operator.itemgetter(1))
                        for key, value in sortedlist:  # Iterate over list - last assigned value is the largest file
                            largestfile = key
                            largestsize = value
                        sys.stdout.write(
                            "\r\n" +
                            g.PIPE +
                            "Decompressing and using largest file in archive: %s (%s bytes)." %
                            (largestfile,
                             largestsize))
                        file = zip_file_object.open(largestfile)
                        listfile = file.read()
                    else:
                        listfile = data

                    print "\r\n" + g.PIPE + "Searching from %s lines." % (linecount) + c.END
                    totalLines = totalLines + linecount
                    output = self.matchfinder(listfile.splitlines())
                    for line in output:
                        printl(line)
                printp("A total of %s lines searched, %s cached files updated." % (totalLines, cacherefreshcount))
                if len(matchcollector) > 0:
                    i = 0
                    printp("Found %s matches:" % len(matchcollector))
                    for line in matchcollector:
                        i += 1
                        printl("%s: %s" % (i, line))
            except Exception as ex:
                printe("Block list error {}".format(ex),c.R)

    def spam_list(self):
        if self.arg.spamlists:
            try:
                printh("Querying spamlists for %s..." % self.IPaddr)
                for bl in self.sourceListSpamDNS:
                    try:
                        my_resolver = dns.resolver.Resolver()
                        query = '.'.join(reversed(str(self.IPaddr).split("."))) + "." + bl
                        answers = my_resolver.query(query, "A")
                        answer_txt = my_resolver.query(query, "TXT")
                        print g.PIPE + c.Y + 'IP: %s IS listed in %s (%s: %s)' % (self.IPaddr, bl, answers[0], answer_txt[0]) + c.END
                    except dns.resolver.NoAnswer:
                        ()
                    except dns.resolver.NXDOMAIN:
                        printl('IP: %s is NOT listed in %s' % (self.IPaddr, bl))
            except Exception as ex:
                printe("Block list error {}".format(ex), c.R)

    def whois(self):
        if self.arg.whois:
            try:
                results = results2 = ""
                try:
                    results = subprocess.check_output("whois " + self.IPaddr, shell=True)
                except subprocess.CalledProcessError:
                    printe("Whois returned an error.", "Whois")
                if self.Domain != "":
                    try:
                        results2 = subprocess.check_output("whois " + self.Domain, shell=True)
                    except subprocess.CalledProcessError:
                        printe("Whois returned an error.", "Whois")
                if results:
                    printh("Querying IP Address %s" % self.IPaddr)
                    for line in results.splitlines():
                        if ("abuse" in line and "@" in line) or "address" in line or "person" in line or "phone" in line:
                            printl(line, c.B)
                        elif "descr" in line:
                            printl(line, c.Y)
                        else:
                            printl(line)
                if results2:
                    printh("Resolved address %s for domain %s" % (self.IPaddr, self.Domain))
                    for line in results2.splitlines():
                        if len(line) >= 80:
                            line = line[0:80] + c.Y + "..." + c.END
                        if "#" in line:
                            ()
                        elif ("abuse" in line and "@" in line) or "address" in line or "person" in line or "phone" in line:
                            printl(line, c.B)
                        elif "descr" in line:
                            printl(line, c.Y)
                        else:
                            printl(line)
            except Exception as ex:
                printe("Error in who is",c.R)

    def scan_ports(self):
        if self.arg.scanports or self.arg.scanheaders:
            printh("Scanning common ports...")
            socket.setdefaulttimeout(3)
            openports = []
            try:
                for port in self.targetPortscan:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    result = sock.connect_ex((self.IPaddr, port))
                    if result == 0:
                        printl("port %s is open." % port, c.G)
                        openports.append(port)
                    else:
                        printl("port %s is closed." % port)
                    sock.close()
                if self.arg.scanheaders and self.Domain != "":
                    for port in openports:
                        url = "http://" + self.Domain
                        try:
                            if port == 443:
                                protocol = "https://"
                            else:
                                protocol = "http://"
                            pipe()
                            printp("Getting headers for %s%s:%s" % (protocol, self.Domain, port))
                            page = requests.head(
                                '%s%s:%s' %
                                (protocol, self.Domain, port), headers={
                                    'user-agent': random.choice(self.uapool), 'referer': 'https://www.google.com'})
                            print g.PIPE + c.BOLD + "Server response code: %s" % page.status_code + c.END
                            for key, value in page.headers.items():
                                printl("%s: %s" % (key, value))
                        except Exception as e:
                            printe(str(e), "Headerscan")
            except KeyboardInterrupt:
                printe("Caught Ctrl+C, interrupting...")
            except socket.gaierror:
                printe("Could not connect to address.")
            except socket.error:
                printe("Couldn't connect to server.")

    def openssl(self):
        if self.arg.cert and (self.IPaddr != "" or self.Domain !=""):
            try:
                results = None
                try:
                    results = subprocess.check_output(
                        "echo | openssl s_client -showcerts -servername %s -connect %s:443 2>/dev/null | openssl x509 -inform pem -noout -text 2>/dev/null" %
                        (self.Domain,self.Domain), shell=True)
                    if results:
                        printh("Certificate information for https://%s/" % self.Domain)
                        for line in results.splitlines():
                            if "Issuer" in line or "Subject:" in line or "DNS:" in line or "Not Before" in line or "Not After" in line:
                                printl(line.replace("  ", " "), c.B)
                            else:
                                printl(line.replace("  ", " "))
                except subprocess.CalledProcessError:
                    printe("OpenSSL returned an error.", "OpenSSL")
            except Exception as ex:
                printe("Error with opensl {}".format(ex),c.R)

