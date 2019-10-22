
from entry import Setup,domain_check
import dns
import socket
import IPy
from IPy import IP
from print_msg import *
import scan

if __name__ == '__main__':
    setup = Setup()
    arg = setup.args_setup()
    settings = setup.config_file_check()
    IPS = []
    DOMAINS = []

    if (arg.ip or arg.domain) and (arg.IPlist or arg.Domainlist):
        printe("Specify List file or single value, not both! Exiting...", c.R)
        exit()
    if arg.ip:
        if setup.validate_ip(arg.ip):
            IPaddr = arg.ip
            Domain = ""
            IPS.append(IPaddr)
        else:
            printe("Invalid IP address, exiting...", "Validate IP")
            exit()
    elif arg.domain:
        IPaddr, Domain = domain_check(arg.domain)
        DOMAINS.append(Domain)
        IPS.append(IPaddr)
    elif arg.IPlist:
        with open(arg.IPlist) as IPfile:
            for line in IPfile.readlines():
                if setup.validate_ip(line.strip()):
                    IPS.append(line.strip())
                else:
                    printe("Invalid IP address {}, passing...".format(line.strip()), "Validate IP")
                    pass
    elif arg.Domainlist:
        with open(arg.Domainlist) as Domainfile:
            for line in Domainfile.readlines():
                IPaddr, Domain = domain_check(arg.domain)
                IPS.append(IPaddr)
                DOMAINS.append(Domain)
    else:
        printe("No target given, exiting...", "Target")
        exit()

    try:
        socket.gethostbyaddr('8.8.8.8')
    except:
        printe('No Internet Access','Connection')
        exit()

    for IP in IPS:
        s = scan.Scan(IP=IP, Domain='', Settings=settings, arg=arg)
        s.scan_all()
        del s

    for domain in DOMAINS:
        d = scan.Scan(IP='', Domain=domain, Settings=settings, arg=arg)
        d.scan_all()
        del d
