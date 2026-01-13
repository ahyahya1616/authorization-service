FROM eclipse-temurin:17-jre-alpine

LABEL maintainer="yassinekamouss"

VOLUME /tmp

ARG JAR_FILE=target/*.jar

COPY ${JAR_FILE} app.jar

# Configuration par défaut
ENV JAVA_OPTS=""

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app.jar"]