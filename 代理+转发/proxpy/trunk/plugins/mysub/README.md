# mysub
sub..sub..

需要的其它组件：

python的Flask框架；
Flask-Bootstrap插件；
sqlmapapi；
proxpy开源代理；
mysql数据库。

使用方法：

在mysql中创建mysub数据库，然后在该数据库中建表：
CREATE TABLE `sub_sqli` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `taskid` varchar(100) NOT NULL,
  `url` varchar(256) NOT NULL,
  `body` varchar(8192) DEFAULT NULL,
  `sqli` int(11) DEFAULT NULL,
  `data` varchar(8192) DEFAULT NULL,
  `hash` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1

把代码目录放在proxpy代理目录中的plugin目录下，修改config/config.py中相关配置参数，在config/targetdomain文件中输入要检测的域名列表。



