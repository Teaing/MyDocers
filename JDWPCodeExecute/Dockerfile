FROM tomcat:8

MAINTAINER Tea <Tea@love.com>
LABEL CHALLENGE="JDWP Code Execute"

ENV CATALINA_OPTS="-server -Xdebug -Xnoagent -Djava.compiler=NONE -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=5005"

EXPOSE 8080 5005
CMD ["catalina.sh", "run"]
