package app.attestation.server;

import org.apache.commons.dbutils.QueryRunner;
import org.sqlite.SQLiteConfig;
import org.sqlite.SQLiteDataSource;

import java.sql.Connection;
import java.sql.SQLException;

final class SQLUtil {

    static final int BUSY_TIMEOUT = 10 * 1000;

    static QueryRunner initQueryRunner(final String dbPath, final boolean readOnly) {
        SQLiteConfig config = new SQLiteConfig();
        config.setReadOnly(readOnly);
        config.setBusyTimeout(BUSY_TIMEOUT);
        config.setJournalMode(SQLiteConfig.JournalMode.WAL);
        config.enforceForeignKeys(true);

        SQLiteDataSource dataSource = new SQLiteDataSource(config);
        dataSource.setUrl("jdbc:sqlite:" + dbPath);

        return new QueryRunner(dataSource);
    }

    static Connection initTransaction(final QueryRunner queryRunner) throws SQLException {
        Connection conn = queryRunner.getDataSource().getConnection();
        conn.setAutoCommit(false);

        return conn;
    }

    private SQLUtil() {
        throw new UnsupportedOperationException();
    }
}
