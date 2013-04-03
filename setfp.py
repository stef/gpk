#!/usr/bin/env python

import sys, struct, hashlib, traceback, datetime
from pgpdump import utils
from pgpdump.packet import old_tag_length
from Crypto.PublicKey import RSA
from Crypto import Random

def help():
    print "usage: $0 <secret key> <public key> <seconds since 1970/01/01>"
    sys.exit(1)

def patchkey(key, i, rsakey, fp):
    # find signature packet
    offset=0
    # must be secret/public key packet type
    if ((key[0] & 0x3f) >> 2) not in [5, 6]:
        print "data does not start with a key packet"
        sys.exit(1)
    o2, l = old_tag_length(key,offset)
    datestart=offset+2+o2
    offset+=1 + o2 + l
    # next must be keyid packet type
    if ((key[offset] & 0x3f) >> 2) !=13:
        print "packet is not a keyid"
        sys.exit(1)
    # nothing to see here - skip to next
    o2, l = old_tag_length(key,offset)
    offset+=1 + o2 + l
    # next packet must be signature packet type
    if ((key[offset] & 0x3f) >> 2)!=2:
        print "packet is not a signature"
        sys.exit(1)
    # skip to end of hashed data
    o2, l = old_tag_length(key,offset)
    offset+=struct.unpack('!H', str(key[offset+5+o2:offset+7+o2]))[0]+7+o2
    #print "end of hashed data:", offset
    #print ' '.join(["%02x" % x for x in key[offset:offset+32]])
    if not key[offset+2:offset+4]==bytearray([9,0x10]):
        print "issuer not found"
        sys.exit(1)

    # calculate hash of data to be signed
    hash=hashlib.sha1(str(key[:offset])).digest()

    # find out offset to store the keys
    hstart=offset+struct.unpack('!H', str(key[offset:offset+2]))[0]+2

    # patch date
    key[datestart:datestart+4]=struct.pack('!i',i)

    # patch issuer id
    key[offset+4:offset+12]=fp[-8:]

    # sign and patch the key
    sig = rsakey.sign(hash, Random.get_random_bytes(20))

    sig=utils.get_int_bytes(sig)
    siglen=len(sig)*8

    patch=''.join([hash[-2:],
                   struct.pack('!H',siglen),
                   str(sig)])
    key[hstart:hstart+len(patch)]=patch

def loadkey(fname):
    try:
        inf=open(fname,'rb')
    except:
        print traceback.format_exc()
        print "error opening", fname
        help()
    key=bytearray(inf.read())
    inf.close()
    return key

def getrsaparams(key):
    if key[0]!=0x95:
        print "first param must be a secret key"
        sys.exit(1)

    offset=9 # start of key material
    n, offset = utils.get_mpi(key, offset)
    n=long(n)
    #print 'n', offset, "%x" % n
    e, offset = utils.get_mpi(key, offset)
    e=long(e)
    #print 'e', offset, "%x" % e
    d, offset = utils.get_mpi(key, offset+1)
    #print 'd', offset, "%x" % d
    p, offset = utils.get_mpi(key, offset)
    #print 'p', offset, "%x" % p
    q, offset = utils.get_mpi(key, offset)
    #print 'q', offset, "%x" % q
    u, offset = utils.get_mpi(key, offset)
    #print 'u', offset, "%x" % u
    return RSA.construct(([n, e, d, p, q, u]))

def savekey(fname, key):
    try:
        outf=open(fname,'wb')
    except:
        print traceback.format_exc()
        print "error opening new key", fname
        help()
    outf.write(key)
    outf.close()

def getnewfp(key, i):
    # patch date
    offset, length = old_tag_length(key,0)
    buffer=bytearray(''.join(['\x99',
                              struct.pack('!H', length),
                              str(key[offset+1:offset+1+length])]))
    buffer[4:8]=struct.pack('!i',i)
    #print "%02x %02x %02x %02x" % tuple(map(int,key[4:8]))
    m = hashlib.sha1()
    m.update(str(buffer))
    print 'setting new fingerprint:', m.hexdigest()[-16:], i, datetime.datetime.fromtimestamp(i)
    return m.digest()

if __name__ == "__main__":
    if len(sys.argv)!=4: help()
    # get new date
    try:
        i=int(sys.argv[3])
    except:
        print traceback.format_exc()
        help()
    # load public key
    pkey=loadkey(sys.argv[2])
    fp=getnewfp(pkey, i)

    # open secret key
    skey=loadkey(sys.argv[1])
    rsakey=getrsaparams(skey)
    patchkey(skey, i, rsakey, fp)
    savekey(sys.argv[1]+'-new', skey)

    # patch public key
    patchkey(pkey, i, rsakey, fp)
    savekey(sys.argv[2]+'-new', pkey)
