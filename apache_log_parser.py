import heapq
from collections import Counter
import re
import os
import sys
filename= sys.argv[1]
with open(filename, 'r') as f1:
    clientip = []
    status = []
    upath = []
    for line in f1:
        sp=line.split()
        clientip.append(sp[0])
        status.append(sp[8])
        upath.append(sp[6])
    fast = Counter(clientip)
    maximumi = dict(Counter(fast).most_common(10))
    url = Counter(upath)
    maximumu = dict(Counter(upath).most_common(10))
    s = Counter(status)
    maximums = dict(Counter(status).most_common(10))
    print(maximumi)
    print(maximumu)
    print(maximums)

