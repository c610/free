#!/usr/bin/env python3
# suff_monitor.py -- basic monitoring for fuzzing scenarios (suff/burp/mutiny)
# 
# -- updates --
# 22.11.2023 @ 02:23 :: shame init version ready to go
# 21.11.2023 @ 19:18 :: log me if you can
# 21.11.2023 @ 15:14 :: added: time, sleep, log2fp
# 21.11.2023 @ 01:19 :: started this lame code
# 
# idea - run suff_monitor.py against the box you're testing (fgvm):
# - add time to sleep and date to log updates
# - log in (so same creds as for suff.py, postauth testing, etc)
# - get ver/info -> log2file
# ** (should be ready at this stage, so): **
#   while true:
#       check_diag_deb(+log2file,+a)
#       sleep 1
#  end_of_file
# 
# -------------
# 
# for more details:
#   https://code610.blogspot.com/2023/04/fuzzing-fortigate-7.html  
#   https://github.com/c610/free/blob/master/suff-v0.1.py
#   https://github.com/c610/free/blob/master/fg7stack_poc.py
# 
# 


from netmiko import Netmiko
import sys,os
import time
import paramiko


###################
##############
########
####
##
#

fplog = open('saveme.log','+a')

command = 'diag debug crashlog show' # did you enable logs in your FGVM?


def connect_to_crashlog():
 
    
    # set up for the target
    try:
        
        fw_01 = {
          'host':'192.168.56.231',
          'username':'admin',
          'password':'P@ssw0rd',
          'device_type':'fortinet',
          'timeout':3
          }

        net_connect = Netmiko( **fw_01 )
        print("+ Connected to FG!")
        print("+    logfile: savethis.log")

        fplog.write('----starting suff_monitor.py ----\n')
        fplog.write(net_connect)  
        fplog.write('\n-- results below: --\n')

        # if we're connected: check diag debug crashlog (or any other you'd like to)
        send_logcheck_cfg = net_connect.send_config_set( command  ) 
        
        fplog.write(send_logcheck_cfg)
        fplog.write('\n---- next while loop ----\n')
        
        print("+ looks like we just sent this command:\n\t%s\n\n" % send_logcheck_cfg )

        print("send_init_cfg finished")


    ## check crashlog finished 


    except paramiko.ssh_exception.SSHException as e:
        print(" > connection error: %s" % e)

    except ConnectionResetError as e:
        print("> connection error2: %s" % e)

    except UnboundLocalError as e:
        print("UnboundLocalError: local variable 'net_connect' referenced before assignment")
        print("> unbound variable error: %s" % e)

## end of connect_to_crashlog() 
# 

##########
#### main
##########

print('y0;[')
print('starting: connect_to_crashlog()')

while True:

    print('debug: connect_to_crashlog() starting...')

    connect_to_crashlog()

    print("... sleeping 1...")
    time.sleep(1) 

    print('sleep done. next True iter...')
    

#### 
print("finished main()")










