#!python

# invoke with
# python ./genkeyid.py keyring.pub 2>gpk.snapshots | grep --color -i -f keycandidates | tee fps

import hashlib, struct, time, datetime, sys
from pgpdump.packet import old_tag_length

inkey=open(sys.argv[1],'rb')
pubkey=inkey.read()
inkey.close()

now=time.time()

try:
    # resume from last snapshot
    i=int(sys.argv[2])
except:
    i=0

# patch date
offset, length = old_tag_length(bytearray(pubkey),0)
header=''.join(['\x99',
                struct.pack('!H', length),
                pubkey[offset+1:offset+2]])
trailer=pubkey[offset+6:offset+1+length]
while i<now:
    m = hashlib.sha1()
    m.update(''.join([header,
                      struct.pack('!i',i),
                      trailer]))
    print m.hexdigest()[-8:], i, "%02x %02x %02x %02x" % struct.unpack('!BBBB',struct.pack('!i',i)), datetime.datetime.fromtimestamp(i)
    i+=1
    if i%1000000==0:
        print >>sys.stderr, m.hexdigest(), i, datetime.datetime.fromtimestamp(i)
        now=time.time()

