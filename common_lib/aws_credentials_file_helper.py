#!/usr/bin/python3
# -*- coding: UTF-8 -*-
from math import fabs
import os
from tempfile import mkstemp
from shutil import move, copymode
from os import fdopen, remove
from pathlib import Path
from io import TextIOWrapper


class AwsCredentialsFileHelper(object):
  """
      Call in a loop to create terminal progress bar
      @params:
          account_name                - Required : aws account name
          aws_access_key_id           - Required : aws account access key id
          aws_secret_access_key       - Required : aws account secret key id
          aws_session_token           - Required : aws account session token
          aws_account_default_region  - Required : aws account region
          aws_account_role_name       - Required : aws account role name
          aws_profile_name            - Required : aws account and role profile name
          set_as_default_aws_profile  - Optional : the profile must be set as default profile
      """
  def __init__(self, 
                aws_account_name: str,
                aws_access_key_id: str,
                aws_secret_access_key: str, 
                aws_session_token: str,
                aws_account_default_region:str,
                aws_account_role_name:str,
                aws_profile_name:str,
                set_as_default_aws_profile:bool=False) -> None:
    self.aws_account_name = aws_account_name
    self.aws_access_key_id = aws_access_key_id
    self.aws_secret_access_key = aws_secret_access_key
    self.aws_session_token = aws_session_token
    self.aws_account_default_region = aws_account_default_region
    self.aws_account_role_name = aws_account_role_name
    self.aws_profile_name= aws_profile_name 
    self.set_as_default_aws_profile = set_as_default_aws_profile

  def __update_line(self, current_line:str, variable_name:str, variable_value:str) -> tuple:
    line_updated = False
    new_line:str = current_line
    if not current_line.endswith(f"{variable_value}\n"):
      new_line = f"{variable_name} = {variable_value}\n"
      line_updated = True
    return (line_updated, new_line)

  def update_credentials(self):
    home = str(Path.home())
    aws_config_path = os.path.join(home, ".aws")
    if not os.path.exists(aws_config_path):
      os.makedirs(aws_config_path)
    
    aws_config_file_path = os.path.join(aws_config_path, "credentials")
    if not os.path.exists(aws_config_file_path):
        open(aws_config_file_path, 'a').close()
    
    credentials_updated = False
    default_credentials_updated = False
    current_credentials_file_lines:list[str] = []
    new_current_credentials_file_lines:list[str] = []
    with open(aws_config_file_path,'r') as current_file:
      current_credentials_file_lines.extend(current_file.readlines())

    profile_found = False
    default_profile_found = False
    update_finished = False
    for line in current_credentials_file_lines:
      line_updated = False
      new_line:str = line if line.endswith("\n") else f"{line}\n"
      if line.lower().startswith(f"[{self.aws_profile_name.lower()}]"):
        profile_found = True
      elif line.lower().startswith("[default]"):
        default_profile_found=True
      elif (profile_found or (self.set_as_default_aws_profile and default_profile_found)) and not update_finished:
        if line.startswith("["):
          update_finished = True
        elif line.startswith("aws_access_key_id"):
          (line_updated, new_line) = self.__update_line(current_line=line,
                                              variable_name="aws_access_key_id",
                                              variable_value=self.aws_access_key_id)
        elif line.startswith("aws_secret_access_key"):
          (line_updated, new_line) = self.__update_line(current_line=line,
                                              variable_name="aws_secret_access_key",
                                              variable_value=self.aws_secret_access_key)
        elif line.startswith("aws_session_token"):
          (line_updated, new_line) = self.__update_line(current_line=line,
                                              variable_name="aws_session_token",
                                              variable_value=self.aws_session_token)
        elif line.startswith("region"):
          (line_updated, new_line) = self.__update_line(current_line=line,
                                              variable_name="region",
                                              variable_value=self.aws_account_default_region)
        if line_updated:
          if profile_found:
            credentials_updated = True
          elif default_profile_found: 
            default_credentials_updated = True
      new_current_credentials_file_lines.append(new_line)
        
    if not profile_found:
      credentials_updated = True
      self.add_credentials_profile(new_current_credentials_file_lines=new_current_credentials_file_lines,
                                                        aws_profile_name = self.aws_profile_name,
                                                        aws_access_key_id = self.aws_access_key_id,
                                                        aws_secret_access_key = self.aws_secret_access_key,
                                                        aws_session_token = self.aws_session_token,
                                                        aws_account_default_region = self.aws_account_default_region)
      

    if not default_profile_found and self.set_as_default_aws_profile and not default_credentials_updated:
      default_credentials_updated = True
      self.add_credentials_profile(new_current_credentials_file_lines=new_current_credentials_file_lines,
                                                        aws_profile_name = "default",
                                                        aws_access_key_id = self.aws_access_key_id,
                                                        aws_secret_access_key = self.aws_secret_access_key,
                                                        aws_session_token = self.aws_session_token,
                                                        aws_account_default_region = self.aws_account_default_region,
                                                        append_on_beginnig=True)

    # Creating a temp file
    if credentials_updated or default_credentials_updated:
      temp_file_fd, temp_file_abspath = mkstemp()
      try:
          with fdopen(temp_file_fd,'w') as file_temp:
              # with open(aws_config_file_path,'r') as current_file:
            for line in new_current_credentials_file_lines:
              file_temp.write(line)

          # copymode(aws_config_file_path, temp_file_abspath)
          # remove(aws_config_file_path)
          move(temp_file_abspath, aws_config_file_path)
          print(f"Credentials from profile {self.aws_profile_name} updated")
      finally:
        if os.path.exists(temp_file_abspath):
          remove(temp_file_abspath)
    else:
      print(f"Nothing done: Credentials from profile {self.aws_profile_name} alread updated")

  def add_credentials_profile(self, 
                              new_current_credentials_file_lines:list[str],
                              aws_profile_name:str,
                              aws_access_key_id:str,
                              aws_secret_access_key:str,
                              aws_session_token:str,
                              aws_account_default_region:str,
                              append_on_beginnig:bool=False) -> None:
      credential_lines:list[str] = []
      
      if len(new_current_credentials_file_lines) > 0 and new_current_credentials_file_lines[-1] != '\n':
        credential_lines.append(f"\n")
      
      credential_lines.append(f"[{aws_profile_name}]\n")
      credential_lines.append(f"aws_access_key_id = {aws_access_key_id}\n")
      credential_lines.append(f"aws_secret_access_key = {aws_secret_access_key}\n")
      credential_lines.append(f"aws_session_token = {aws_session_token}\n")
      credential_lines.append(f"region = {aws_account_default_region}\n")
      credential_lines.append(f"\n")
      

      if append_on_beginnig:
        index=0
        for new_line in credential_lines:
          new_current_credentials_file_lines.insert(index, new_line)
          index = index + 1
      else:
        new_current_credentials_file_lines.extend(credential_lines)
