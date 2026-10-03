alter table proxy.apps
  add column aws_region text check (aws_region ~ '^[a-z]{2}(-[a-z]+)+-[0-9]$'),
  add column aws_service text;

alter table proxy.apps drop constraint apps_auth_type_check;
alter table proxy.apps add constraint apps_auth_type_check
  check (auth_type in ('none', 'bearer', 'api_key_header', 'basic', 'aws_sigv4'));

alter table proxy.apps drop constraint apps_check1;
alter table proxy.apps add constraint apps_auth_secret_check
  check (auth_type in ('none', 'aws_sigv4') or num_nonnulls(auth_secret_ciphertext, auth_secret_env) = 1);

alter table proxy.apps add constraint apps_aws_sigv4_check
  check (auth_type <> 'aws_sigv4' or (aws_region is not null and aws_service is not null));
