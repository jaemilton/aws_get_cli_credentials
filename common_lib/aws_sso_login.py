#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import logging
import os, boto3, json
from botocore.exceptions import ProxyConnectionError, ClientError
from common_lib.selenium_sso_login import SeleniumSsoLogin
from common_lib.aws_credentials_file_helper import AwsCredentialsFileHelper
from exceptions.aws_custom_errors import AwsSsoUserCodeAuthorizationException, AwsForbiddenException
from botocore.config import Config
from datetime import datetime
from collections import OrderedDict
from cacheout import Cache
from retry import retry

import os

print()


class AwsSsoLogin(object):
  """
  
    Exemplo adaptado de https://aws.plainenglish.io/session-token-generator-aws-sso-with-aad-b07872268a86
    AwsSsoLogin login on aws and update the credential on file ~/.aws/credentials
    @params:
      aws_sso_start_url                     --> Required, url for single sigle on (sso) on aws portal
      aws_sso_region                        --> Required, aws region to realize single sign on (sso) login
      aws_accounts_default_region           --> Required, aws region to be set together with aws accounts credentials profile
      otp_2fa_devide_id                     --> Optional, aws one time password (OTP) two factory authentication (2fa) device id, to ne used to generate de token for login on single sigle on (sso) on aws portal
      aws_username                          --> Required, aws user name to login on single sigle on (sso) on aws portal
      aws_password                          --> Required, aws user password to login on single sigle on (sso) on aws portal
      aws_account_id                        --> Optional, aws account id that must have the credentials updated, if not set, all accounts found will be updated
      aws_account_profile_name              --> Optional, aws account profile name that must have the credentials updated, if not set, all accounts found will be updated
      custom_aws_profile_name               --> Optional, custom name to be set do profile name, when set, if only one account found, the profile will assume this name, otherwise, the profile will have the name {aws_account_name}_{aws_account_role_name}
      aws_default_account_profile_name      --> Optional, Optional, profile name with must credentials set as default profile
      proxy                                 --> Optional, proxy to be used for aws api calls
      ssl_verify                            --> Optional, if not set will be True. The values can be True|False|CA Certificate file path to be used on ssl connections
      selenium_aws_sso_transition_timeout   --> Optional, single sign on (sso) transaction timeout in seconds between login pages
      debug
  """
  GRANT_TYPE="urn:ietf:params:oauth:grant-type:device_code"
  CACHE_PATH=f"{os.path.dirname(os.path.abspath(__file__))}/.cached"
  CACHE_PATH_EXPIRE_TIMES=f"{os.path.dirname(os.path.abspath(__file__))}/.cached_expire_times"
  def __init__(self,
                aws_sso_start_url:str,
                aws_sso_region:str,
                aws_accounts_default_region:str,
                otp_2fa_devide_id: str,
                aws_username:str,
                aws_password:str,
                aws_account_id:str=None,
                aws_account_profile_name:str=None,
                custom_aws_profile_name:str=None,
                aws_default_account_profile_name:str=None,
                proxy:dict = None,
                ssl_verify = None,
                selenium_aws_sso_transition_timeout:int = 60, #60 seconds
                debug:bool=False) -> None:
    self.aws_sso_region = aws_sso_region
    self.aws_accounts_default_region = aws_accounts_default_region
    self.aws_sso_start_url = aws_sso_start_url
    self.otp_2fa_devide_id = otp_2fa_devide_id
    self.aws_username = aws_username
    self.aws_password = aws_password
    self.aws_account_id = aws_account_id
    self.aws_account_profile_name = aws_account_profile_name
    self.custom_aws_profile_name = custom_aws_profile_name
    self.aws_default_account_profile_name = aws_default_account_profile_name
    self.ssl_verify = ssl_verify
    self.selenium_aws_sso_transition_timeout = selenium_aws_sso_transition_timeout
    self.debug = debug
    self.force_device_authorization_update = False
    self.force_aws_sso_token = False
    logging.basicConfig()

    self.sso_oidc = None
    self.sso_client = None
    self._config=None
    if  proxy is not None:
      self._config = Config(proxies={'https': f'{proxy}'})
    self._load_cache()
 
  def _load_cache(self):
    self.cached = Cache()
    expire_times:dict=None
    cache_contents:OrderedDict=None
    if os.path.exists(self.CACHE_PATH_EXPIRE_TIMES):
      with open(self.CACHE_PATH_EXPIRE_TIMES) as file:
        expire_times = json.load(file)

    if os.path.exists(self.CACHE_PATH):
      with open(self.CACHE_PATH) as file:
        cache_contents = json.load(file)
        for cache_key in cache_contents:
          if cache_key is not None:
            if expire_times is not None and cache_key in expire_times:
                expires_at = datetime.fromtimestamp(expire_times[cache_key])
                if expires_at > datetime.now():
                    ttl=(expires_at - datetime.now()).seconds
                    self.cached.set(key=cache_key, value=cache_contents[cache_key], ttl=ttl)

  def __dump_cache(self, cache_path:str, json_dump:str):
    if os.path.exists(cache_path):
      os.remove(cache_path)

    with open(cache_path, "a") as file:
      file.write(json_dump)

  def _save_cache(self):
    self.__dump_cache(self.CACHE_PATH, json.dumps(self.cached.copy()))
    self.__dump_cache(self.CACHE_PATH_EXPIRE_TIMES, json.dumps(self.cached.expire_times()))

  def _get_sso_client(self):
    if self.sso_client is None:
      self.sso_client = boto3.client('sso', region_name=self.aws_sso_region, config=self._config, verify=self.ssl_verify)
    return self.sso_client

  def _get_sso_oidc_client(self):
    if self.sso_oidc is None:
      self.sso_oidc = boto3.client('sso-oidc', region_name=self.aws_sso_region, config=self._config, verify=self.ssl_verify)
    return self.sso_oidc

  def __get_cached_value(self, key:str, func_get_value, force_update:bool=False, **kwargs):
    cached_value = self.cached.get(key)
    if force_update or cached_value is None:
      (cached_value, ttl) = func_get_value(**kwargs)
      if cached_value is not None:
        self.cached.set(key=key, value=cached_value, ttl=ttl)
        self._save_cache()
    return cached_value

  @retry(ProxyConnectionError, tries=5, delay=1, backoff=10, logger=logging)
  def __get_aws_client(self, **_):
    """
    $ aws sso-oidc register-client --client-name jaemilton --client-type public --region us-east-1

    {
        "clientId": "ZnG6...",
        "clientSecret": "eyJra...",
        "clientIdIssuedAt": 1657568341,
        "clientSecretExpiresAt": 1665344341
    }
    """
    client = self._get_sso_oidc_client().register_client(clientName = 'client-1', clientType = 'public')
    timestamp = int(client.get("clientSecretExpiresAt"))
    ttl = (datetime.fromtimestamp(timestamp) - datetime.now()).seconds
    return (client, ttl)

  @retry((ProxyConnectionError), tries=5, delay=1, backoff=10, logger=logging)
  def __get_aws_token(self, **_):
    """
    $ aws sso-oidc create-token \
    > --client-id ZnG6... \
    > --client-secret eyJra... \
    > --grant-type urn:ietf:params:oauth:grant-type:device_code \
    > --device-code U-cRFyk... \
    > --code VRV... \
    > --region us-east-1

    {
        "accessToken": "eyJlbmMiOi...",
        "tokenType": "Bearer",
        "expiresIn": 28800
    }
    """
    client = self._get_sso_oidc_client()
    token = None
    ttl=0
    client_id=self.get_client_id()
    client_secret=self.get_client_secret()
    device_code=self.get_device_code()
    if client_id is not None and client_secret is not None and device_code is not None:
      try:
        token = client.create_token(clientId=client_id,
                                      clientSecret=client_secret,
                                      grantType=self.GRANT_TYPE,
                                      deviceCode=device_code)
        ttl = int(token.get("expiresIn"))
      except ClientError as exception :
        if type(exception).__name__ == "InvalidGrantException" or type(exception).__name__ == "AuthorizationPendingException":
          self.force_device_authorization_update=True     
        else:
          raise exception
# , 
    return (token, ttl)

  @retry(ProxyConnectionError, tries=5, delay=1, backoff=10, logger=logging)
  def __get_list_aws_account_roles(self, found_token, account_id:int):
    """
    Get aws list accout roles from an account_id
    $ aws sso list-account-roles \
    > --access-token eyJl... \
    > --account-id 466469... \
    > --region us-east-1

    {
      "roleList": [
          {
              "roleName": "DEVELOPER_ACCESS",
              "accountId": "46646..."
          }
      ]
    }
    """
    if found_token:
      roles_response = self._get_sso_client().list_account_roles(nextToken=found_token,accessToken=self.get_sso_access_token(), accountId=account_id)
    else:
      roles_response = self._get_sso_client().list_account_roles(accessToken=self.get_sso_access_token(), accountId=account_id)
    return roles_response

  def __get_sso_list_account_roles_loop(self, **kwargs):
    """
    Get list of account_roles from an account_id
    """
    list_account_roles=[]
    account_id = kwargs.get('account_id')
    more_objects = True
    found_token = ""
    while more_objects:
      account_roles = self.__get_list_aws_account_roles(found_token, account_id)
      for account_role in account_roles['roleList']:
        if 'roleName' in account_role:
            list_account_roles.append(account_role)

      # Now check there is more objects to list
      if 'nextToken' in account_roles:
        found_token = account_roles['nextToken']
        more_objects = True
      else:
        break
    ttl = 43200  #12 hours
    return (list_account_roles, ttl)


  
  @retry(ProxyConnectionError, tries=5, delay=1, backoff=10, logger=logging)
  def __get_account_role_credentials(self, **kwargs) :
    """
    Get credentials from a specific account_id and role_name
    ws sso get-role-credentials \
    > --role-name DEVELOPER_ACCESS \
    > --account-id 466469... \
    > --access-token eyJlbmM... \
    > --region us-east-1

    {
      "roleCredentials": {
          "accessKeyId": "ASIAWZG...",
          "secretAccessKey": "s9OpYP0...",
          "sessionToken": "IQoJb3JpZ2l...",
          "expiration": 1657587680000
      }
    }
    """
    account_id = kwargs.get('account_id')
    role_name = kwargs.get('role_name')
    access_token=self.get_sso_access_token()
    try:
      sts_credentials = self._get_sso_client().get_role_credentials(accessToken=access_token,
                                                                    accountId=account_id,
                                                                    roleName=role_name)
    except ClientError as exception :
        if type(exception).__name__ == "ForbiddenException":
          self.force_aws_sso_token=True  
          raise AwsForbiddenException


    timestamp = int(sts_credentials.get("roleCredentials").get("expiration")/1000)
    ttl = (datetime.fromtimestamp(timestamp) - datetime.now()).seconds
    return (sts_credentials, ttl)

  @retry(ProxyConnectionError, tries=5, delay=1, backoff=10, logger=logging)
  def __get_list_accounts(self, found_token):
    """
      Get accounts associate to a single sign on login
      $ aws sso list-accounts \
      > --access-token eyJlbmM... \
      > --region us-east-1

      {
        "accountList": [
            {
                "accountId": "848768...",
                "accountName": "account-A-hom",
                "emailAddress": "email@mail.com"
            },
            {
                "accountId": "969166...",
                "accountName": "account-B-hom",
                "emailAddress": "email@mail.com"
            },
            {
                "accountId": "436938...",
                "accountName": "account-A-dev",
                "emailAddress": "email@mail.com"
            },
            {
                "accountId": "14696...",
                "accountName": "account-B-dev",
                "emailAddress": "email@mail.com"
            },
            ...
        ]
      }
    """
    accounts=None
    access_token=self.get_sso_access_token()
    if access_token is not None:
      if found_token:
        accounts = self._get_sso_client().list_accounts(nextToken=found_token, accessToken=access_token)
      else:
        accounts = self._get_sso_client().list_accounts(accessToken=access_token)
    else:
      raise Exception("Access Token not found")
    return accounts

  def __get_sso_list_accounts(self, **_):
    """
      Get all accounts associate to a single sign on login
    """
    list_accounts = []
    more_objects = True
    found_token = None
    while more_objects:
      accounts = self.__get_list_accounts(found_token)
      for account in accounts['accountList']:
        if 'accountId' in account:
            list_accounts.append(account)

      # Now check there is more objects to list
      if 'nextToken' in accounts:
        found_token = accounts['nextToken']
        more_objects = True
      else:
        break
    
    ttl = 43200  #12 hours
    return (list_accounts, ttl)

  @retry(ProxyConnectionError, tries=5, delay=1, backoff=10, logger=logging)
  def __get_aws_device_authorization(self, **_):
    """
    $ aws sso-oidc start-device-authorization \
    > --client-id ZnG6G4HtS... \
    > --client-secret eyJra... \
    > --start-url https://xpto.awsapps.com/start/ \
    > --region us-east-1

    {
        "deviceCode": "U-cRFy...",
        "userCode": "VRV...",
        "verificationUri": "https://device.sso.us-east-1.amazonaws.com/",
        "verificationUriComplete": "https://device.sso.us-east-1.amazonaws.com/?user_code=VR...",
        "expiresIn": 600,
        "interval": 1
    }
    """
    device_authorization = self._get_sso_oidc_client().start_device_authorization(clientId=self.get_client_id(),
                                                                    clientSecret=self.get_client_secret(),
                                                                    startUrl=self.aws_sso_start_url)
    ttl = int(device_authorization.get("expiresIn"))
    self.force_device_authorization_update=False
    return (device_authorization, ttl)

  def _get_aws_client(self):
    return self.__get_cached_value(key="client",func_get_value= self.__get_aws_client)

  def _get_aws_device_authorization(self):
    return self.__get_cached_value(key="device_authorization", 
                                    func_get_value=self.__get_aws_device_authorization,
                                    force_update=self.force_device_authorization_update)

  def get_client_id(self):
    return self._get_aws_client().get('clientId')

  def get_client_secret(self):
    return self._get_aws_client().get('clientSecret')

  def get_device_code(self):
    return self._get_aws_device_authorization().get('deviceCode')

  def _get_aws_sso_token(self, force_aws_sso_token: bool = False):
    return self.__get_cached_value(key="token", func_get_value=self.__get_aws_token, force_update=force_aws_sso_token)

  def get_sso_access_token(self):
    return None if self._get_aws_sso_token(self.force_aws_sso_token) is None else self._get_aws_sso_token().get("accessToken")

  def _get_list_accounts(self):
    return self.__get_cached_value(key="list_accounts", func_get_value=self.__get_sso_list_accounts)


  def _get_account_by_attr_name(self, searched_value:str, attr_name:str):
    account_found = None
    list_account = self.__get_cached_value(key="list_accounts", func_get_value=self.__get_sso_list_accounts)
    for account in list_account:
      if searched_value.lower().startswith(account[attr_name].lower()):
        account_found = account
        break
    return account_found

  def _get_account_by_id(self):
    return self._get_account_by_attr_name(self.aws_account_id, "accountId")

  def _get_account_name(self):
    return self._get_account_by_attr_name(self.aws_account_profile_name, "accountName")

  def _get_sso_list_account_roles(self):
    """
    Get all roles associated with aws account_id  
    """
    list_account_roles = []
    for account in self._get_list_accounts():
      account_id = account['accountId']
      list_account_roles.append(self.__get_cached_value(key=f"list_account_roles_{account_id}", 
                                                        func_get_value=self.__get_sso_list_account_roles_loop, 
                                                        account_id=account_id)
                                )
    return list_account_roles

  def _get_sso_list_account_roles_by_account_id(self, account_id):
    return self.__get_cached_value(key=f"list_account_roles_{account_id}", 
                                    func_get_value=self.__get_sso_list_account_roles_loop, 
                                    account_id=account_id)

  def _get_sso_account_role_credentials(self, account_id:int, role_name:str) :
    """
    Get role credentials for a specific account_id and role_name
    """
    return self.__get_cached_value(key=f"account_role_credentials_{account_id}_{role_name}", 
                                    func_get_value=self.__get_account_role_credentials, 
                                    account_id=account_id,
                                    role_name=role_name)
    
  @retry(AwsSsoUserCodeAuthorizationException, tries=2, delay=2, backoff=2, logger=logging)
  def aws_sso_authorize(self)-> None:
      if self.get_sso_access_token() is None:
        authz = self._get_aws_device_authorization()
        url = authz.get('verificationUri')
        user_code = authz.get('userCode')
          
        selenium_sso_login = SeleniumSsoLogin(aws_username=self.aws_username,
                                                aws_password=self.aws_password,
                                                user_code=user_code,
                                                logon_url=url,
                                                aws_otp_device_id = self.otp_2fa_devide_id,
                                                selenium_aws_sso_transition_timeout=self.selenium_aws_sso_transition_timeout,
                                                debug = self.debug)
        try:
          selenium_sso_login.login_and_allow()
        except AwsSsoUserCodeAuthorizationException as ex:
          self.force_device_authorization_update=True
          raise ex
      

  @retry(AwsForbiddenException, tries=2, delay=2, backoff=2, logger=logging)     
  def start(self) -> None:

    can_have_custom_profile_name = False
    self.aws_sso_authorize()
    aws_accounts = []
    if self.aws_account_id is not None:
      can_have_custom_profile_name = True
      account_found = self._get_account_by_id()
      if account_found is not None:
        aws_accounts.append(account_found)
    elif self.aws_account_profile_name is not None:
      can_have_custom_profile_name = True
      account_found = self._get_account_name()
      if account_found is not None:
        aws_accounts.append(account_found)
    else:
      aws_accounts.extend(self._get_list_accounts())

    if len(aws_accounts) > 0:
      #get and save all account credentials
      for account in aws_accounts:
        account_id = account["accountId"]
        aws_account_name = account["accountName"]
        
        print(f">>> Credentials found for account {aws_account_name} ({account_id})")
        
        account_roles = self._get_sso_list_account_roles_by_account_id(account["accountId"])
        there_are_multiple_roles = (len(account_roles)> 1)
        for account_role in account_roles:
          aws_account_role_name = account_role["roleName"]
          profile_name = f"{aws_account_name}_{aws_account_role_name}"

          set_as_default_aws_profile:bool = self.aws_default_account_profile_name == profile_name
          credencials = self._get_sso_account_role_credentials(account_id=account_id, role_name=aws_account_role_name)
          custom_aws_profile_name = self.custom_aws_profile_name if (can_have_custom_profile_name and self.custom_aws_profile_name is not None and (self.aws_account_profile_name is not None or not there_are_multiple_roles)) else profile_name

          if credencials is not None:
            print(f"Updating credentials from accounf {aws_account_name} ({account_id})")
            aws_access_key_id = credencials.get("roleCredentials").get("accessKeyId")
            aws_secret_access_key = credencials.get("roleCredentials").get("secretAccessKey")
            aws_session_token = credencials.get("roleCredentials").get("sessionToken")
            aws_credentials_file_helper = AwsCredentialsFileHelper(aws_account_name=aws_account_name,
                                                                  aws_access_key_id=aws_access_key_id,
                                                                  aws_secret_access_key=aws_secret_access_key,
                                                                  aws_session_token=aws_session_token,
                                                                  aws_account_default_region=self.aws_accounts_default_region,
                                                                  aws_account_role_name=aws_account_role_name,
                                                                  aws_profile_name = custom_aws_profile_name,
                                                                  set_as_default_aws_profile=set_as_default_aws_profile)
            aws_credentials_file_helper.update_credentials()
    else:
      print("There are no account found.")
