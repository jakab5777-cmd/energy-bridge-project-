-- Migration: clients + normalized IP management schema
-- ADDITIVE ONLY. Existing tables (wan_solutions, ip_tunnels, real_ips,
-- credentials, dsp_providers, vlan_tracking, etc.) are NOT touched, dropped,
-- or modified. New tables use a _v2 suffix where a name collision with an
-- existing table would otherwise occur, so nothing live is at risk.
-- Data migration from old tables into these new ones is a separate,
-- deliberate step — not part of this migration.

CREATE TABLE IF NOT EXISTS clients (
    client_id SERIAL PRIMARY KEY,
    client_name VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS dsp_providers_v2 (
    dsp_id SERIAL PRIMARY KEY,
    dsp_name VARCHAR(255),
    code_name VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS vlans_v2 (
    vlan_id INTEGER PRIMARY KEY,
    status VARCHAR(50),
    type VARCHAR(50),
    service VARCHAR(100),
    zone VARCHAR(100),
    client_id INTEGER REFERENCES clients(client_id),
    real_ip VARCHAR(50),
    fake_ip VARCHAR(50),
    dsp_id INTEGER REFERENCES dsp_providers_v2(dsp_id)
);

CREATE TABLE IF NOT EXISTS real_ip_subnets (
    real_ip_id SERIAL PRIMARY KEY,
    real_ip_block VARCHAR(100),
    client_id INTEGER REFERENCES clients(client_id),
    fake_ip VARCHAR(100),
    vlan_id INTEGER REFERENCES vlans_v2(vlan_id),
    dsp_id INTEGER REFERENCES dsp_providers_v2(dsp_id),
    wan VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS internal_ip_subnets (
    internal_ip_id SERIAL PRIMARY KEY,
    internal_ip_block VARCHAR(100),
    client_id INTEGER REFERENCES clients(client_id),
    other_ips TEXT
);

CREATE TABLE IF NOT EXISTS wan_solutions_v2 (
    wan_id SERIAL PRIMARY KEY,
    client_id INTEGER REFERENCES clients(client_id),
    head_office VARCHAR(100),
    branch_code VARCHAR(100),
    branch_name VARCHAR(255),
    vlan_id INTEGER REFERENCES vlans_v2(vlan_id),
    dsp_id INTEGER REFERENCES dsp_providers_v2(dsp_id),
    upload_download VARCHAR(100),
    subnet_ho_to_branch VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS ip_tunnels_v2 (
    tunnel_id SERIAL PRIMARY KEY,
    client_id INTEGER REFERENCES clients(client_id),
    local_ip VARCHAR(100),
    remote_ip VARCHAR(100),
    interface VARCHAR(100),
    description TEXT
);

CREATE TABLE IF NOT EXISTS vpns (
    vpn_id SERIAL PRIMARY KEY,
    client_id INTEGER REFERENCES clients(client_id),
    vpn_type VARCHAR(100),
    vpn_ip VARCHAR(100),
    username VARCHAR(255),
    password VARCHAR(255),
    description TEXT
);

CREATE TABLE IF NOT EXISTS credentials_v2 (
    credential_id SERIAL PRIMARY KEY,
    subnet VARCHAR(100),
    gateway VARCHAR(100),
    vlan_id INTEGER REFERENCES vlans_v2(vlan_id),
    net_desc TEXT,
    ip_address VARCHAR(100),
    node_type VARCHAR(100),
    device_desc TEXT,
    username VARCHAR(255),
    password VARCHAR(255),
    login_url TEXT,
    additional TEXT
);
