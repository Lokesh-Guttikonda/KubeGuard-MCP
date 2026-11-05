FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY target/payments-api.jar /app/app.jar
ENV JAVA_TOOL_OPTIONS="-Xmx768m -XX:+UseG1GC -XX:+ExitOnOutOfMemoryError"
USER 10001
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
