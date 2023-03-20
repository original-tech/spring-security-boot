create table oauth_client_details (
  client_id VARCHAR(256) PRIMARY KEY,
  resource_ids VARCHAR(256),
  client_secret VARCHAR(256),
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(256),
  authorities VARCHAR(256),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4096),
  autoapprove VARCHAR(256)
);
INSERT INTO `oauth_client_details` VALUES ('c1', 'res1',
'$2a$10$NlBC84MVb7F95EXYTXwLneXgCca6/GipyWR5NHm8K0203bSQMLpvm', 'ROLE_ADMIN,ROLE_USER,ROLE_API',
'client_credentials,password,authorization_code,implicit,refresh_token', 'https://www.baidu.com',
NULL, 7200, 259200, NULL, 'false');
INSERT INTO `oauth_client_details` VALUES ('c2', 'res2',
'$2a$10$NlBC84MVb7F95EXYTXwLneXgCca6/GipyWR5NHm8K0203bSQMLpvm', 'ROLE_API',
'client_credentials,password,authorization_code,implicit,refresh_token', 'https://www.baidu.com',
NULL, 31536000, 2592000, NULL, 'false');


-- http://localhost:3001/oauth/authorize?client_id=c1&response_type=code&scope=ROLE_ADMIN&redirect_uri=https://www.baidu.com
-- http://localhost:3001/oauth/authorize?client_id=c2&response_type=code&scope=ROLE_API&redirect_uri=https://www.baidu.com

create table oauth_code (
  code VARCHAR(256), authentication blob
);

select * from oauth_client_details;


