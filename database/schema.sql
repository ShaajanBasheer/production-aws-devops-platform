CREATE TABLE security_events (
    id SERIAL PRIMARY KEY,
    source VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    username VARCHAR(255),
    source_ip VARCHAR(45),
    endpoint VARCHAR(500),
    status_code INTEGER,
    message VARCHAR(2000),
    timestamp TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_security_events_source_ip
    ON security_events(source_ip);

CREATE INDEX idx_security_events_timestamp
    ON security_events(timestamp);
