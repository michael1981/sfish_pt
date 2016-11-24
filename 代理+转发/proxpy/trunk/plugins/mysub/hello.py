#encoding=utf-8
from flask import Flask, render_template, redirect, url_for
from flask.ext.bootstrap import Bootstrap
app = Flask(__name__)
bootstrap = Bootstrap(app)

from lib.sqlimanage import SqliManage
import config.config as conf

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sqli')
def sqli():
    sqlimanage = SqliManage(conf.sqlmapapi_url, conf.admin_id)
    sqlimanage.handle_result()
    sqliresult = sqlimanage.get_sqli_result()  
    sqlitesting = sqlimanage.get_scaning_list()
    return render_template('sqli.html', sqliresult=sqliresult, sqlitesting=sqlitesting)

@app.route('/sqli/tasks_clean')
def sqli_tasks_clean():
    sqlimanage = SqliManage(conf.sqlmapapi_url, conf.admin_id)
    sqlimanage.tasks_clean()
    return redirect(url_for('sqli'), code=302)

@app.route('/sqli/clean_db')
def sqli_clean_db():
    sqlimanage = SqliManage(conf.sqlmapapi_url, conf.admin_id)
    sqlimanage.clean_db()
    return redirect(url_for('sqli'), code=302)

if __name__ == '__main__':
    app.run()

