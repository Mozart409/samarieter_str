-- Add up migration script here
CREATE TABLE IF NOT EXISTS tenants (
	id integer PRIMARY KEY AUTOINCREMENT,
	name text NOT NULL,
	public_id text NOT NULL UNIQUE,
	created_at text NOT NULL,
	updated_at text NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
	id integer PRIMARY KEY AUTOINCREMENT,
	email text NOT NULL UNIQUE,
	pwd_hash text NOT NULL,
	public_id text NOT NULL UNIQUE,
	created_at text NOT NULL,
	updated_at text NOT NULL,
	tenant_id int NOT NULL,
	FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE ON UPDATE NO ACTION
);
