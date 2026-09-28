CREATE TABLE IF NOT EXISTS change_logs (
    log_id SERIAL PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    record_id INTEGER NOT NULL,
    action VARCHAR(10) NOT NULL,
    changed_by INTEGER REFERENCES registered_users(user_id),
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    old_data JSONB,
    new_data JSONB
);

CREATE INDEX idx_logs_table_record ON change_logs(table_name, record_id);
CREATE INDEX idx_logs_user ON change_logs(changed_by);
