#encoding=utf-8
import sys
sys.path.append('..')

import json
import base64
import time
import hashlib
import config.config as conf
from urlparse import urlparse
from http import do_get, do_post
from db import Mysql

#日志记录
def log(tag, message):
    f = open(conf.sqlimanage_log, 'a+')
    f.write('[%s] %s: %s\n' % (time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time())), tag, message))
    f.close()
    return

#sql注入管理类
class SqliManage(object):
    def __init__(self, sqlmapapiurl, adminid):
        self.sqlmapapiurl = sqlmapapiurl #SQLMAP API服务地址
        self.adminid = adminid #SQLMAP API adminid
        self.mysql = Mysql(conf.db_host, conf.db_port, conf.db_user, conf.db_pass, conf.db_name)
        
    #获取当前任务列表
    def _get_task_list(self):
        checkurl = self.sqlmapapiurl + '/admin/' + self.adminid + '/list';
        resp = json.loads(do_get(checkurl))
        return resp['tasks']
    
    #漏洞结果入库
    def _item2db(self, taskid):
        dataurl = self.sqlmapapiurl + '/scan/' + taskid + '/data';
        resp = json.loads(do_get(dataurl))
        data = resp['data']
        if data != []:
            dset = "data='%s', sqli=1" % base64.b64encode(str(data[0]))
        else:
            dset = "sqli=0"
        where = "taskid='%s'" % taskid
        self.mysql.update('sub_sqli', dset, where)   
        return
    
    #删除已完成的任务
    def _delete_task(self, taskid):
        deleteurl = self.sqlmapapiurl + '/task/' + taskid + '/delete'
        do_get(deleteurl)
        return
    
    #处理任务结果
    def handle_result(self):
        tasklist = self._get_task_list()
        for taskid, state in tasklist.items():
            if state == 'terminated':
                self._item2db(taskid)
                self._delete_task(taskid)
        return
    
    #sqli任务初入库
    def _task2db(self, taskid, url, body, psw):
        self.mysql.insert('sub_sqli', ('taskid', 'url', 'body', 'hash'), (taskid, url, body, psw))
        return    
    
    #创建SQLI任务
    def send2sqlmap(self, url, user_agent='', cookie='', body=''):
        flag, psw = self._is_need_sqli_test(url, body)
        if not flag:
            return False
        newurl = self.sqlmapapiurl + '/task/new'
        resp = json.loads(do_get(newurl))
        taskid = resp['taskid']
        log('send2sqlmap', 'task is created. id : %s' % taskid)
        data = {}
        data['url'] = url
        if cookie != '' and cookie != []:
            data['cookie'] = cookie[0]
        data['headers'] = 'User-Agent: ' + user_agent[0]
        if body != '':
            data['data'] = body
        starturl = self.sqlmapapiurl + '/scan/' + taskid + '/start'
        do_post(starturl, user_agent[0], cookie, json.dumps(data))
        log('send2sqlmap', 'task is started. id : %s' % taskid)
        self._task2db(taskid, url, body, psw)
        return True
    
    #检测该请求是否需要进行SQLI测试
    def _is_need_sqli_test(self, url, body):
        parsedurl = urlparse(url)
        if parsedurl.query == '' and body == '':
            return False, ''  
        test = parsedurl.netloc + parsedurl.path + parsedurl.params + parsedurl.query
        m = hashlib.md5()
        m.update(test)
        psw = m.hexdigest()
        for one in self.mysql.select(('hash'), 'sub_sqli'):
            if psw == one[0]:
                return False, ''
        f = open('plugins/mysub/config/targetdomain', 'r')
        domains = f.readlines()
        f.close()
        for one in domains:
            if one[:-1] in parsedurl.netloc:
                return True, psw
        return False, ''
    
    #获取漏洞结果
    def get_sqli_result(self):
        return self.mysql.select(('url', 'body', 'data'), 'sub_sqli', 'sqli=1')
        
    #获取正在进行的任务列表
    def get_scaning_list(self):
        return self.mysql.select(('url', 'body'), 'sub_sqli', 'sqli is NULL')
    
    #强行善后
    def tasks_clean(self):
        tasklist = self._get_task_list()
        for taskid in tasklist:
            self._delete_task(taskid)
        self.mysql.delete('sub_sqli', 'sqli is NULL')
        return
    
    #清库
    def clean_db(self):
        self.mysql.delete('sub_sqli')
        return
    
        
    

