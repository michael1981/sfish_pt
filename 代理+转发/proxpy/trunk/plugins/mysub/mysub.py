#encoding=utf-8
import sys
sys.path.append('plugins/mysub')

import json
import time
import config.config as conf
from lib.http import do_get, do_post
from lib.db import Mysql
from lib.sqlimanage import SqliManage

#日志记录
def log(tag, message):
    f = open(conf.mysub_log, 'a+')
    f.write('[%s] %s: %s\n' % (time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time())), tag, message))
    f.close()
    return

#sql注入测试模块
def sqli_test(req):
    sqlimanage = SqliManage(conf.sqlmapapi_url, conf.admin_id)
    user_agent = req.getHeader("User-Agent")
    cookie = req.getHeader("Cookie")
    body = req.body
    url = req.url
    if req.method == 'CONNECT':
        url = 'https://' + url  
    if sqlimanage.send2sqlmap(url, user_agent, cookie, body):
        log('sqli_test', '%s' % url)
    return

def proxy_mangle_request(req):
    sqli_test(req)
    return req

def proxy_mangle_response(res):
    return res

