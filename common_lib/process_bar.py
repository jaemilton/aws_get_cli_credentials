#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from datetime import datetime
from datetime import timedelta
from select import select
import math

class ProcessBar(object):
  """
      Call in a loop to create terminal progress bar
      @params:
          total_iteration       - Required  : total iterations (Int)
          start_interator       - Optional  : with interation number is the start interation
          prefix      - Optional  : prefix string (Str)
          suffix      - Optional  : suffix string (Str)
          decimals    - Optional  : positive number of decimals in percent complete (Int)
          length      - Optional  : character length of bar (Int)
          fill        - Optional  : bar fill character (Str)
          printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
      """
  def __init__(self, 
                    total_iteration: int,
                    start_interator: int = 0,
                    prefix: str = 'Progress:', 
                    suffix: str = 'Complete', 
                    decimals:int = 1, 
                    length: int = 100,
                    fill:str = '█',
                    print_end: str = "\r") -> None:
        self._total_iteration = total_iteration -1 if start_interator==0 else total_iteration
        self._start_interator = start_interator
        self._prefix = prefix
        self._suffix = suffix
        self._decimals = decimals
        self._length = length
        self._fill = fill
        self._print_end = print_end
        self.__starded = False
        self._last_percentage = 0
        self._delta_time:timedelta = timedelta(seconds=0)
        self._total_delta_time:timedelta = timedelta(seconds=0)
        self.__TTF:timedelta = timedelta(seconds=0)
        self.__max_message_length:int = 0
        

  def start(self) -> None:
    self._start_date_time_update = datetime.now()
    self._last_date_time_update = datetime.now()
    self.__starded = True
    self.print_progress_bar(self._start_interator)

  # Print iterations progress
  def print_progress_bar(self, iteration: int):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
    """

    if not self.__starded:
      self.start()

    percent = ("{0:." + str(self._decimals) + "f}").format(math.floor(100 * math.pow(10 , self._decimals) * (iteration / float(self._total_iteration)))/math.pow(10 , self._decimals))
    if (percent != self._last_percentage):
        self._last_percentage = percent
        self._delta_time = (datetime.now() - self._last_date_time_update)
        self._total_delta_time = (datetime.now() - self._start_date_time_update)
        if iteration > self._start_interator:
          self.__TTF = timedelta(seconds=int(((self._total_iteration - iteration)  * self._total_delta_time.total_seconds()) / iteration))
        self._last_date_time_update = datetime.now()
        filled_length = int(self._length * iteration // self._total_iteration)
        bar = self._fill * filled_length + '-' * (self._length - filled_length)
        message = f'\r{self._prefix} |{bar}| {percent}% {self._suffix} - Time {self._total_delta_time}, TTF {self.__TTF}'
        self.__max_message_length = max(self.__max_message_length, len(message))
        if iteration == self._total_iteration:
          print(message.ljust(self.__max_message_length))
        else:
          print(message.ljust(self.__max_message_length), end = self._print_end)