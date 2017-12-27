#!/usr/bin/python
'''Generate a rainbow table compatible with challenger.py tool'''

import sys, struct, binascii, os
from Crypto.Hash import MD4

def md4hash(word):
    h = MD4.new()
    h.update(b'' + word)
    return h.hexdigest()

def main():
    f = open('wordlist.txt', 'r')
    for line in f:
        uline = line.strip().decode('latin-1').encode('utf-16-le')
        theHash = md4hash(uline)
        lastA = theHash[28:30]
        lastB = theHash[30:32]
        print "%s : %s" % ((lastA + lastB), uline)

        filename = 'rainbowtable/'+lastA+'/'+lastB
        directory = os.path.dirname(filename)

        if not os.path.exists(directory):
            os.makedirs(directory)

        o = open(filename, 'a')
        o.write(line.strip() + "\n")

if __name__ == "__main__":
    main()
