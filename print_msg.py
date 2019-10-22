

class c:
    HDR = '\033[96m'
    B = '\033[94m'
    Y = '\033[93m'
    G = '\033[92m'
    R = '\033[91m'
    D = '\033[90m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UL = '\033[4m'

class g:
    STAR = c.D + "[" + c.G + "*" + c.D + "] " + c.END
    PLUS = c.D + "[" + c.END + c.BOLD + "+" + c.D + "] " + c.END
    PIPE = c.D + " |  " + c.END
    FAIL = c.D + "[" + c.R + "!" + c.D + "] " + c.END
    MINUS = c.D + "[-] " + c.END



def printe(message, module):
    if module != "":
        print g.FAIL + c.R + ("%s: %s" % (module, message)) + c.END
    else:
        print g.FAIL + c.R + ("%s" % message) + c.END

def printh(message):
    print g.STAR + c.HDR + message + c.END

def printp(message):
    print g.PLUS + c.END + message

def printl(message, color = ""):
    print g.PIPE + color + message + c.END

def pipe():
    print c.D + g.PIPE + c.END