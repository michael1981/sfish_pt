#encoding=utf-8
import urllib2

#GET请求
def do_get(url, user_agent='', cookie=''):
    req = urllib2.Request(url)
    if cookie == '':
        req.add_header('Cookie', cookie)
    if user_agent == '':
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.118 Safari/537.36')
    else:
        req.add_header('User-Agent', user_agent)
    resp = urllib2.urlopen(req)
    return resp.read()

#POST请求
def do_post(url, user_agent='', cookie='', data=''):
    if data == '':
        data = {}
    req = urllib2.Request(url, data=data, headers={'Content-Type': 'application/json'})
    if cookie != '':
        req.add_header('Cookie', cookie)
    if user_agent == '':
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.118 Safari/537.36')
    else:
        req.add_header('User-Agent', user_agent)
    resp = urllib2.urlopen(req)
    return resp.read()