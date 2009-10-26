create table keys (
	id integer primary key autoincrement,
	subject varchar(2000) unique,
	cert_data varchar(3000),
	private_key varchar(3000) unique);
