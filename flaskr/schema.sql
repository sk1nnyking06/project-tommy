DROP TABLE IF EXISTS user;

CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  company_name TEXT NOT NULL,
  company_city TEXT NOT NULL,
  company_country TEXT NOT NULL,
  company_state TEXT NOT NULL
);
