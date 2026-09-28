CREATE TABLE IF NOT EXISTS hardware_assets (
    asset_id SERIAL PRIMARY KEY,
    device_name VARCHAR(100) NOT NULL,
    serial_number VARCHAR(100) UNIQUE,
    model VARCHAR(100),
    firmware_version VARCHAR(50),
    status VARCHAR(50) DEFAULT 'In Storage',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS isp_staff (
    staff_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES registered_users(user_id) ON DELETE CASCADE,
    department VARCHAR(100),
    position VARCHAR(100),
    access_level VARCHAR(50) DEFAULT 'Technician'
);
