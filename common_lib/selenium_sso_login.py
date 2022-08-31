#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import os
from common_lib.common_error import BadUserInputError
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.edge.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from common_lib.otp_helper import OtpHelper
from exceptions.aws_custom_errors import AwsSsoUserCodeAuthorizationException
from selenium.common.exceptions import NoSuchElementException, TimeoutException


class SeleniumSsoLogin(object):
  """
      SeleniumSsoLogin login on aws from sso portal
      @params:
          aws_username                            - Required  : aws user name for login
          aws_password                            - Required  : aws user password for login
          user_code                               - Required  : user account genetared from sso_oidc.start_device_authorization service
          logon_url                               - Optional  : aws url for login, if not set will assume https://device.sso.us-east-1.amazonaws.com/
          aws_otp_device_id                       - Optional  : aws otp device id to genetare 2fa code
          selenium_aws_sso_transition_timeout     - Optional  : aws timeout between eatch page transaction from sso login pages
          debug                                   - Optional  : debug flag with default = false, if true, will sholl egde browser
      """
  
  SUBMIT_BUTTON_ELEMENT = "//button[@type='submit']"

  def __init__(self, 
                aws_username:str,
                aws_password:str,
                user_code:str,
                logon_url:str= 'https://device.sso.us-east-1.amazonaws.com/',
                aws_otp_device_id:str = None,
                selenium_aws_sso_transition_timeout:int = 60,
                debug:bool = False) -> None:
    
    self.EDGE_DRIVER = os.environ["EDGE_DRIVER_PATH"]
    if not os.path.exists(self.EDGE_DRIVER):
      BadUserInputError(f"Edge driver {self.EDGE_DRIVER} not found")
    self._aws_username = aws_username
    self._aws_password = aws_password
    self._user_code = user_code
    self._logon_url = logon_url
    self._aws_otp_device_id = aws_otp_device_id
    self.selenium_aws_sso_transition_timeout = selenium_aws_sso_transition_timeout
    self._debug = debug
    self._service = Service(executable_path=self.EDGE_DRIVER)
  
  
  def check_exists_by_xpath(self, browser: webdriver.Edge, xpath):
    try:
        browser.find_element(by= By.XPATH, value=xpath)
    except NoSuchElementException:
        return False
    return True
  
  def login_and_allow(self) -> None:
    browser_options = Options()
    browser_options.headless = not self._debug
    browser_options.add_argument("-inprivate")
    browser = webdriver.Edge(service=self._service, options=browser_options)
    browser.get(self._logon_url)

    wait = WebDriverWait(browser, self.selenium_aws_sso_transition_timeout)
    if '?user_code=' not in self._logon_url:
      wait.until(EC.visibility_of_any_elements_located((By.ID, 'verification_code')))
      browser.find_element(by= By.ID, value="verification_code").send_keys(self._user_code)
      browser.find_element(by= By.XPATH, value="//button[contains(.,'Next')]").click()
    
    try:
        wait.until(EC.visibility_of_any_elements_located((By.ID, 'username-input')))
    except TimeoutException as ex: 
        if self.check_exists_by_xpath(browser=browser, xpath="//b[contains(.,'Authorization failed')]"):
            browser.close()
            raise AwsSsoUserCodeAuthorizationException()
        else:
            raise ex
        
    browser.find_element(by= By.ID, value="awsui-input-0").send_keys(self._aws_username)
    browser.find_element(by= By.XPATH, value=self.SUBMIT_BUTTON_ELEMENT).click()

    wait.until(EC.visibility_of_any_elements_located((By.ID, 'password-input')))
    browser.find_element(by= By.ID, value='awsui-input-1').send_keys(self._aws_password)
    browser.find_element(by= By.XPATH, value=self.SUBMIT_BUTTON_ELEMENT).click()

    if self._aws_otp_device_id is not None:
        wait.until(EC.visibility_of_any_elements_located((By.ID, 'awsui-input-0')))
        otp_helper = OtpHelper(self._aws_otp_device_id)
        browser.find_element(by= By.ID, value='awsui-input-0').send_keys(otp_helper.get_code())
        browser.find_element(by= By.XPATH, value=self.SUBMIT_BUTTON_ELEMENT).click()

    wait.until(EC.visibility_of_any_elements_located((By.ID, 'cli_login_button')))
    browser.find_element(by= By.ID, value='cli_login_button').click()
    wait.until(EC.visibility_of_any_elements_located((By.XPATH, "//b[contains(.,'Request approved')]")))
    browser.close()
    
        
    
    

