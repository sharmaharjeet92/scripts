from selenium import webdriver
import pyautogui
import pyautogui.tweens
from selenium.webdriver.chrome.options import Options
with open ('cred.txt','r') as f:
		for line in f:
			sp=line.split(':')
			username = sp[0]
			password = sp[1]
			browser=webdriver.Chrome("chromedriver")
			browser.get("http://bot.bhanu.xyz/kona/dvwa/login.php")
			#browser.find_element_by_name("username").send_keys(sp[0][0])
			for u in username:
				pyautogui.typewrite(u,interval=.4)
				browser.find_element_by_name("username").send_keys(u)
			#browser.find_element_by_name("password").send_keys(sp[1][0])
			for p in password:
				pyautogui.typewrite(p,interval=.7)
				browser.find_element_by_name("password").send_keys(p)
			pyautogui.moveTo(100,200,2,pyautogui.easeInOutQuad)
			#pyautogui.click()
		browser.find_element_by_css_selector('''#content > form > fieldset > p > input[type="submit"]''').click()

