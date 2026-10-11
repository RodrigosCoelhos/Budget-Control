CREATE TABLE IF NOT EXISTS users (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), username text NOT NULL UNIQUE, name text NOT NULL,
 email text NOT NULL UNIQUE, password_hash text NOT NULL,
 role text NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
 can_create boolean NOT NULL DEFAULT true, can_edit boolean NOT NULL DEFAULT true,
 can_delete boolean NOT NULL DEFAULT true, active boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON users(lower(username));
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower ON users(lower(email));
CREATE TABLE IF NOT EXISTS projects (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, budget numeric(14,2) NOT NULL DEFAULT 0 CHECK(budget>=0),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS project_members (
 project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 PRIMARY KEY(project_id,user_id)
);
CREATE TABLE IF NOT EXISTS expenses (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), project_id uuid NOT NULL REFERENCES projects(id),
 owner_id uuid NOT NULL REFERENCES users(id), title text NOT NULL,
 category text NOT NULL CHECK(category IN ('Hardware','Serviços','Software','Outros')),
 amount numeric(14,2) NOT NULL CHECK(amount>0), method text NOT NULL,
 expense_date date NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS expenses_project_idx ON expenses(project_id);
CREATE INDEX IF NOT EXISTS expenses_owner_idx ON expenses(owner_id);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS reset_tokens (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL
);
