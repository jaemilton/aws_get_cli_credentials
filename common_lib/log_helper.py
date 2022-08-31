#!/usr/bin/python3
# -*- coding: UTF-8 -*-

class LogHelper(object):
  """
      LogHelper to generate log files
      @params:
          log_file_path                   - Required  : log file path
          debug                           - Optional  : debug flag with default = false, if true, will print all log on console eather
      """

  def __init__(self, 
                log_file_path: str,
                debug:bool = True) -> None:
    self.log_file_path =log_file_path
    self.debug = debug
  
  def print_log(self, line:str) -> None:
    with open(self.log_file_path, "a", newline='') as myfile:
      myfile.write(f"{line}\n")
    if self.debug:
      print(line)