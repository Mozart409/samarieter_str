-- Add up migration script here
CREATE TABLE IF NOT EXISTS items (
	id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	name text NOT NULL,
	amount text NOT NULL,
	created_at text NOT NULL,
	updated_at text NOT NULL,
	tenant_id integer NOT NULL,
	FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);

CREATE INDEX IF NOT EXISTS idx_items_tenant_id ON items(tenant_id);
