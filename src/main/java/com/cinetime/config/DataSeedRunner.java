package com.cinetime.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

@Component
public class DataSeedRunner implements CommandLineRunner {

    private static final Logger LOGGER = LoggerFactory.getLogger(DataSeedRunner.class);
    private static final String[] SEED_EXTENSIONS = {".dat", ".sql", ".txt"};

    private final DataSource dataSource;
    private final JdbcTemplate jdbcTemplate;

    @Value("${app.seed.enabled:false}")
    private boolean enabled;

    @Value("${app.seed.sql-path:}")
    private String seedPath;

    public DataSeedRunner(DataSource dataSource, JdbcTemplate jdbcTemplate) {
        this.dataSource = dataSource;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(String... args) throws Exception {
        if (!enabled) {
            LOGGER.info("Seed runner disabled (app.seed.enabled=false).");
            return;
        }

        if (seedPath == null || seedPath.isBlank()) {
            LOGGER.warn("Seed runner enabled but app.seed.sql-path is empty.");
            return;
        }

        Path path = Paths.get(seedPath);
        if (!Files.exists(path)) {
            LOGGER.warn("Seed path not found: {}", path);
            return;
        }

        if (hasExistingData()) {
            LOGGER.info("Seed data already present; skipping import.");
            return;
        }

        List<String> statements = splitStatements(readSeedContent(path));
        executeStatements(statements);
    }

    private boolean hasExistingData() {
        try {
            Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users", Integer.class);
            return count != null && count > 0;
        } catch (Exception ex) {
            LOGGER.warn("Unable to check existing data; assuming empty database.", ex);
            return false;
        }
    }

    private String readSeedContent(Path path) throws IOException {
        if (Files.isDirectory(path)) {
            LOGGER.info("Seed directory detected: {}", path);
            List<Path> files = listSeedFiles(path);
            StringBuilder builder = new StringBuilder();
            for (Path file : files) {
                LOGGER.info("Loading seed file: {}", file);
                builder.append(Files.readString(file, StandardCharsets.UTF_8));
                int length = builder.length();
                if (length > 0 && builder.charAt(length - 1) != ';') {
                    builder.append(';');
                }
            }
            return builder.toString();
        }

        LOGGER.info("Seed file detected: {}", path);
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    private List<Path> listSeedFiles(Path directory) throws IOException {
        List<Path> files = new ArrayList<>();
        try (var stream = Files.list(directory)) {
            stream.filter(Files::isRegularFile)
                    .filter(file -> hasSeedExtension(file.getFileName().toString()))
                    .sorted((left, right) -> left.getFileName().toString()
                            .compareToIgnoreCase(right.getFileName().toString()))
                    .forEach(files::add);
        }
        return files;
    }

    private boolean hasSeedExtension(String fileName) {
        String lower = fileName.toLowerCase();
        for (String ext : SEED_EXTENSIONS) {
            if (lower.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    private void executeStatements(List<String> statements) throws Exception {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {

            connection.setAutoCommit(false);
            for (String sql : statements) {
                String trimmed = sql.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                statement.execute(trimmed);
            }
            connection.commit();
            LOGGER.info("Seed SQL executed successfully.");
        } catch (Exception ex) {
            LOGGER.error("Seed SQL execution failed.", ex);
            throw ex;
        }
    }

    private List<String> splitStatements(String content) {
        List<String> statements = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inString = false;

        for (int i = 0; i < content.length(); i++) {
            char ch = content.charAt(i);

            if (ch == '\'') {
                if (inString && i + 1 < content.length() && content.charAt(i + 1) == '\'') {
                    current.append(ch);
                    current.append(content.charAt(i + 1));
                    i++;
                    continue;
                }
                inString = !inString;
            }

            if (ch == ';' && !inString) {
                statements.add(current.toString());
                current.setLength(0);
                continue;
            }

            current.append(ch);
        }

        if (current.length() > 0) {
            statements.add(current.toString());
        }

        return statements;
    }
}
