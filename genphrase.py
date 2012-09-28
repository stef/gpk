#!/usr/bin/env python

from Crypto import Random
import struct, sys

wf=open('words','r')
words=wf.readlines()
wf.close()

i=0
res=[]
while i<int(sys.argv[1]):
    idx=len(words)+1
    while idx>len(words):
        idx=struct.unpack('!I', '\0'+Random.get_random_bytes(3))[0]
    res.append(words[idx].strip())
    i+=1
print ' '.join(res)
