
CREATE TABLE turnusers_lt (
    name varchar(512) PRIMARY KEY,
    hmackey char(128)
);

CREATE TABLE turnusers_st (
    name varchar(512) PRIMARY KEY,
    password varchar(512)
);

CREATE TABLE turn_secret (
    value varchar(512)
);

CREATE TABLE allowed_peer_ip (
	ip_range varchar(256)
);

CREATE TABLE denied_peer_ip (
	ip_range varchar(256)
);
