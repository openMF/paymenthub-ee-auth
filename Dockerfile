FROM eclipse-temurin:21-jre
# 5000 = server.port in application.properties
EXPOSE 5000

# The jar is pinned by name instead of copied with a glob and started with
# `java -jar *.jar`: the Gradle build can leave more than one jar in build/libs and
# the glob then picks an arbitrary one. CMD is in exec form so java is PID 1 and
# receives the SIGTERM kubernetes sends on shutdown.
COPY build/libs/app.jar app.jar
CMD ["java", "-jar", "app.jar"]
