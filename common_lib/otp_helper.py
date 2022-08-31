#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import pyotp

class OtpHelper(object):
  """
      Otp to generate OPT device code
      @params:
          log_file_path                   - Required  : log file path
          debug                           - Optional  : debug flag with default = false, if true, will print all log on console eather
      """

  def __init__(self, 
                device_ip: str,
                debug:bool = True) -> None:
    self.device_ip =device_ip
    self.debug = debug
  
  def get_code(self) -> int:
    totp = pyotp.TOTP(self.device_ip)
    return totp.now() # => '492039'