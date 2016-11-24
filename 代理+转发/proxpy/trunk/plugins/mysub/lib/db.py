#encoding=utf-8
import sys
sys.path.append('..')

import MySQLdb
import time
import config.config as conf

#日志记录
def log(tag, message):
    f = open(conf.db_log, 'a+')
    f.write('[%s] %s: %s\n' % (time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time())), tag, message))
    f.close()
    return

#mysql类
class Mysql(object):
    def __init__(self, host='127.0.0.1', port=3306, user='', passwd='', name=''):
        self.host = host
        self.port = port
        self.user = user
        self.passwd = passwd
        self.name = name
        self.conn = MySQLdb.connect(host=self.host, port=self.port, user=self.user, passwd=self.passwd, db=self.name)
        self.cur = self.conn.cursor()
    
    def insert(self, table='', columns=(), values=()):
        sql = 'insert into ' + table + str(columns).replace("'", "") + ' values ' + str(values).replace("(u'", "('") + ';'
        try:
            self.cur.execute(sql)
            self.conn.commit()
            log('Mysql.insert', '%s [success]' % sql)
            return True
        except:
            self.conn.rollback()
            log('Mysql.insert', '%s [fail]' % sql)
            return False
    
    def delete(self, table='', where=''):
        if where == '':
            sql = 'delete from ' + table + ';'
        else:
            sql = 'delete from ' + table + ' where ' + where + ';'
        try:
            self.cur.execute(sql)
            self.conn.commit()
            log('Mysql.delete', '%s [success]' % sql)
            return True
        except:
            self.conn.rollback()
            log('Mysql.delete', '%s [fail]' % sql)
            return False
    
    def update(self, table='', dset='', where=''):
        if where == '':
            sql = 'update ' + table + ' set ' + dset + ';'
        else:
            sql = 'update ' + table + ' set ' + dset + ' where ' + where + ';'
        try:
            self.cur.execute(sql)
            self.conn.commit()
            log('Mysql.update', '%s [success]' % sql)
            return True
        except:
            self.conn.rollback()
            log('Mysql.update', '%s [fail]' % sql)
            return False        
    
    def select(self, columns=(), table='', where=''):
        if where == '':
            sql = 'select ' + str(columns).replace("'", "").replace("(", "").replace(")", "") + ' from ' + table + ';'
        else:
            sql = 'select ' + str(columns).replace("'", "").replace("(", "").replace(")", "") + ' from ' + table + ' where ' + where +';'
        try:
            self.cur.execute(sql)
            log('Mysql.select', '%s [success]' % sql)
            return self.cur.fetchall()
        except:
            log('Mysql.select', '%s [fail]' % sql)
            return False
    
    def __del__(self):
        self.cur.close()
        self.conn.close()
        