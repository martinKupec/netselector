#!/usr/bin/python
from urllib import *
from time import *
from sys import stdout

sleeptime=30
u="username"
pwd="password"

#POST data: buttonClicked=4&err_flag=0&err_msg=&info_flag=0&info_msg=&redirect_url=&username=volec_456&password=virstajn3
while (True):
        stdout.write ("(re)loging on...")
        data=urlencode({"buttonClicked" : "4", "err_flag": "0", "info_flag" : "0", "infomsg" : "", "redirect_url" : "", "username" : u, "password" : pwd})
        try:
                f=urlopen('https://1.1.1.1/login.html', data)
                stdout.write ("ok\n")
        except:
                stdout.write ("failed\n")
        sleep(sleeptime)

