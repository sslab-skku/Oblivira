# Dockerfile for universalresolver/uni-resolver-web

FROM maven:3-jdk-11 AS build
MAINTAINER Markus Sabadello <markus@danubetech.com>

# build uni-resolver-web

ADD . /opt/universal-resolver
ADD config.json /opt/universal-resolver/uni-resolver-web/
RUN cd /opt/universal-resolver && mvn clean install -N -DskipTests
RUN cd /opt/universal-resolver/uni-resolver-core && mvn clean install -N -DskipTests
RUN cd /opt/universal-resolver/driver && mvn clean install -N -DskipTests
RUN cd /opt/universal-resolver/driver-http && mvn clean install -N -DskipTests
RUN cd /opt/universal-resolver/uni-resolver-local && mvn clean install -N -DskipTests
RUN cd /opt/universal-resolver/uni-resolver-web && mvn clean install package -N -DskipTests

# build image
FROM jetty:9.4-jre11
MAINTAINER Markus Sabadello <markus@danubetech.com>

COPY --from=build /opt/universal-resolver/uni-resolver-web/target/*.war /var/lib/jetty/webapps/ROOT.war
COPY --from=build /opt/universal-resolver/uni-resolver-web/config.json /var/lib/jetty/

RUN echo -e "\n\njetty.threadPool.maxThreads=4\njetty.threadPool.minThreads=0" >> /var/lib/jetty/start.d/server.ini

# done

EXPOSE 8080
CMD java -jar /usr/local/jetty/start.jar --add-to-start=jmx,stats,threadpool,threadlimit
CMD java -jar /usr/local/jetty/start.jar -Djetty.http.port=8080
