-- Add up migration script here
CREATE TABLE IF NOT EXISTS tenants (
	id int PRIMARY KEY,
	name text NOT NULL,
	created_at text NOT NULL,
	updated_at text NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
	id int PRIMARY KEY,
	email text NOT NULL UNIQUE,
	pwd_hash text NOT NULL,
	created_at text NOT NULL,
	updated_at text NOT NULL,
	tenant_id int NOT NULL,
	FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE ON UPDATE NO ACTION
);
