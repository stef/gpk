#!/usr/bin/env python
# (c) 2012 s@ctrlc.hu
#
#  This is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.

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
