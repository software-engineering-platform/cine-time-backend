# Stage 1: Build with Maven
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /app

# Copy pom.xml first for better layer caching
COPY pom.xml .

# Download dependencies (cached if pom.xml unchanged)
RUN mvn dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application (skip tests for Docker build)
RUN mvn clean package -DskipTests


# Stage 2: Runtime
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Install wget (required for HEALTHCHECK)
RUN apk add --no-cache wget

# Create non-root user for security
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Copy the built JAR from builder stage
COPY --from=builder /app/target/*.jar app.jar
COPY data/seed /app/data/seed

# Set ownership
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose application port
EXPOSE 8090

# Health check using Spring Boot Actuator
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8090/actuator/health || exit 1

# Run with optimal JVM settings for containers
ENTRYPOINT ["java", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", \
    "app.jar"]
