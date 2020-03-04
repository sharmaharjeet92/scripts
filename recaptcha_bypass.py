import requests
from time import sleep

#this script was created for demostration purposes. Use it responsibly 
# Add these values
API_KEY = '# Your 2captcha API KEY'  
site_key = '# site-key, read the 2captcha docs on how to get this'  
url='captcha_URL'
s = requests.Session()

# here we post site key to 2captcha to get captcha ID (and we parse it here too)
captcha_id1 = s.post("https://2captcha.com/in.php?key=<>&method=userrecaptcha&googlekey=<google-key> "+ url).text
captcha_id=captcha_id1.split('|')[1]
print(captcha_id)# then we parse gresponse from 2captcha response
recaptcha_answer1 = s.get("http://2captcha.com/res.php?key={}&action=get&id={}".format(API_KEY, captcha_id)).text
print("solving ref captcha...")
while 'CAPCHA_NOT_READY' in recaptcha_answer1:
    sleep(5)
    recaptcha_answer1 = s.get("http://2captcha.com/res.php?key={}&action=get&id={}".format(API_KEY, captcha_id)).text
#recaptcha_answer = recaptcha_answer.split('|')[1]
#print(recaptcha_answer1)

recaptcha_answer=recaptcha_answer1.split('|')[1]
# we make the payload for the post data here, use something like mitmproxy or fiddler to see what is needed
payload = {
    'key': 'value',
    'gresponse': recaptcha_answer  # This is the response from 2captcha, which is needed for the post request to go through.
    }

print(payload)
# then send the post request to the url
response = s.post(url, payload)
print(response)

# And that's all there is to it other than scraping data from the website, which is dynamic for every website.nt