#!/usr/bin/python -tt


import os
import sys
import subprocess
filename=sys.argv[1]
with open(filename,'r') as f1:
    for line in f1:
        sp=line.split()
        print(sp[0])
        p1 = subprocess.Popen(["whois", sp[0]], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["grep","Country"], stdin=p1.stdout, stdout=subprocess.PIPE)
        vara=list(p2.communicate())
        print(vara[0])
