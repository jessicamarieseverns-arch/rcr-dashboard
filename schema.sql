CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS session (
    sid VARCHAR NOT NULL COLLATE "default",
    sess JSON NOT NULL,
    expire TIMESTAMP(6) NOT NULL,
    PRIMARY KEY (sid)
);

CREATE INDEX IF NOT EXISTS IDX_session_expire ON session (expire);

INSERT INTO users (email, password, name) VALUES
('admin@rcr.com', '$2b$10$K5W8J5vN5YqJ5vN5YqJ5v.CQN5YqJ5vN5YqJ5vN5YqJ5vN5YqJ5ve', 'Admin User'),
('user@rcr.com', '$2b$10$K5W8J5vN5YqJ5vN5YqJ5v.CQN5YqJ5vN5YqJ5vN5YqJ5vN5YqJ5ve', 'Regular User')
ON CONFLICT (email) DO NOTHING;
