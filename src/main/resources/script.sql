CREATE TABLE usuario(id_usuario serial PRIMARY KEY, nome varchar(60),email varchar(60), senha varchar(255));
CREATE TABLE perfil(id_perfil serial PRIMARY KEY, nome varchar(40));

CREATE TABLE usuario_perfil(id_usuario int references usuario(id_usuario),
							id_perfil int references perfil(id_perfil),
							data_criacao date, constraint pk_usuario_perfil
							PRIMARY KEY(id_usuario,id_perfil));

CREATE TABLE endereco(id_endereco serial PRIMARY KEY, cep varchar(10),
logradouro varchar(50), complemento varchar(30),bairro varchar(40),
localidade varchar(40), uf varchar(2), ibge int);

ALTER TABLE usuario ADD COLUMN id_endereco bigint,
ADD CONSTRAINT FK_ID_ENDERECO
FOREIGN KEY(id_endereco) REFERENCES endereco(id_endereco);