CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    google_id VARCHAR(255),
    username VARCHAR(255),
    email VARCHAR(255),
    password VARCHAR(255)
);

CREATE TABLE users_without ( /*Users that registes without OAuth*/
    id SERIAL PRIMARY KEY,
    username VARCHAR(255),
    email VARCHAR(255),
    password VARCHAR(255)
);

CREATE TABLE session (
    sid VARCHAR PRIMARY KEY,
    sess JSON,
    expire TIMESTAMP
);
