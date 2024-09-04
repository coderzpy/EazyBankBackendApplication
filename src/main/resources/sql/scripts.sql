create table users(username varchar(50) not null primary key,password varchar(500) not null,enabled boolean not null);
create table authorities (username varchar(50) not null,authority varchar(50) not null,constraint fk_authorities_users foreign key(username) references users(username));
create unique index ix_auth_username on authorities (username,authority);

insert ignore into users values('user', '{noop}1234', '1');
insert ignore into authorities values('user', 'read');


insert ignore into users values('admin', '{bcrypt}$2a$12$2IiwIBb4BbwAYSWrywEvp.F0FwepxclAP9b8hd9tvK5QxpeZ3Yto.', '1');
insert ignore into authorities values('user', 'admin');


create table customer (

    id int not null AUTO_INCREMENT,
    email varchar(45) NOT NULL,
    pwd varchar(200) NOT NULL,
    role varchar(45) NOT NULL,
    PRIMARY KEY (id)
);


insert ignore into customer (email, pwd, role) values('user@example.com', '{noop}1234', 'read');
insert ignore into customer (email, pwd, role) values('admin@example.com', '{bcrypt}$2a$12$2IiwIBb4BbwAYSWrywEvp.F0FwepxclAP9b8hd9tvK5QxpeZ3Yto.', 'admin');