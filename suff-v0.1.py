c@ubuntu:~/LABS/_SUFLET2$ cat suff.py
#!/usr/bin/env python3
# suff.py -- simple universal fortigate fuzzer
#
# initial idea : xx.10.2022
# finished idea: xx.04.2023
# 
# special thanks goes to Reykez (https://github.com/Reykez)
# 
# for more details:
#   https://code610.blogspot.com/2023/04/fuzzing-fortigate-7.html  
#

from netmiko import Netmiko
import sys,os
import time
import paramiko


def readFile(filename):
    words = []
    fileText = open(filename.strip(), 'r')
    for line in fileText.readlines():
        for word in line.strip().split():
            words.append(word.strip())
        words.append('\n')
    return words



##

def writeFile(words, filename):
    text = '';

    for word in words:
        text += word;
        if word!='\n':
            text += ' ' ;

    f = open(filename, 'w')
    f.write(text)
    f.close()

    ## run modified payload: send is as cfg:
    fpread = open(filename, 'r')
    lines = fpread.read()

    command = lines

    print("DEBUG :::: type of: %s" % type(command) )
    print( command )
    print("DEBUG :::: eof\n")

    ##
    # set up for the target
    fw_01 = {
        'host':'192.168.56.231',
        'username':'admin',
        'password':'admin',
        'device_type':'fortinet'

    }

    # connecting to the target host
    try:
        net_connect = Netmiko( **fw_01 )
        print("+ connected, checking prompt...")
    except paramiko.ssh_exception.SSHException as e:
        print(" > connection error: %s" % e)

    except ConnectionResetError as e:
        print("> connection error2: %s" % e)

    except UnboundLocalError as e:
        print("UnboundLocalError: local variable 'net_connect' referenced before assignment")
        print("> unbound variable error: %s" % e)

    print("... sleeping 1...")
    time.sleep(2)

    print("> sending fuzzed command...")
    send_init_cfg = net_connect.send_config_set( command  ) # init_cfg...

    print("+ looks like we just sent this command:\n\t%s\n\n" % send_init_cfg )



    ## finished fuzzed super-payload attack
    ##


####

def modifyFilename(filename, number):
    name, extension = os.path.splitext(filename)
    return "{name}{uid}{extension}".format(name=name, uid=str(number).zfill(2), extension=extension)

#### parse and validate command line args, proceed program



args = sys.argv[1:]
filename = args[0] if 0 in range(len(args)) else input ('Filename?')
textToReplace = args[1] if 1 in range(len(args)) else input ('text to replace? ')
outputBasename = args[2] if 2 in range(len(args)) else input ('output basename')

words = readFile(filename);

# reaplce any occurency and print
fileIndex = 0

for wordIndex in range(len(words)):
    if words[wordIndex] == '\n':
        continue
    fileIndex += 1
    wordsCopy = words.copy()
    try:
        wordsCopy[wordIndex] = textToReplace
        writeFile(wordsCopy, modifyFilename(outputBasename, fileIndex ) )

    except UnboundLocalError as e:
        print("UnboundLocalError: local variable 'net_connect' referenced before assignment")
        print("> unbound variable error: %s" % e)
        pass


print('Successfully generated', modifyFilename(outputBasename, 1), '-', modifyFilename(outputBasename, fileIndex), ' files!')









