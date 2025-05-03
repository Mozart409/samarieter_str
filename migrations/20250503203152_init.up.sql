-- Add up migration script here
CREATE TABLE IF NOT EXISTS tenants (
	id int AUTOINCREMENT,
	name TEXT NOT NULL,
	created_at text NOT NULL,
	updated_at text NOT NULL,
);
CREATE TABLE IF EXISTS users(
	id int AUTOINCREMENT,
	email text NOT NULL,
	pwd_hash text NOT NULL,
	created_at text NOT NULL,
	updated_at text NOT NULL,
	FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
