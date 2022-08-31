#!/usr/bin/python3
# -*- coding: UTF-8 -*-
from math import fabs
from signal import signal, SIGINT, SIGTERM
import sys, time
from io import StringIO
import csv
from common_lib.log_helper import LogHelper
import datetime


TIMESTAMP_FORMAT = "{timestamp:.6f}"

def format_timedelta(duration:datetime.timedelta)->str:
    return '{:02}:{:02}:{:02}'.format(duration.seconds // 3600, duration.seconds % 3600 // 60, duration.seconds % 60)



def parse_float(value):
    try:
        return float(value)
    except ValueError:
        return None

def get_input_parameter_value(argv, parameter_identifyer):
    if parameter_identifyer in argv:
        index = argv.index(parameter_identifyer) + 1
        if len(argv) <= index:
            raise ValueError("Error: parameter value for " + parameter_identifyer + " was not defined.")
        else:
            return argv[index]
    else:
        return None


def valid_mandatory_parameters(argv, mandatory_param_array):
    args_count = len(argv)
    return (args_count > 1) and (
                ((args_count -1) >= (len(mandatory_param_array) * 2)) and
                # check if all mandatory param exists on argv
                not any(not (param in argv) for param in mandatory_param_array)
            )

def array_are_equal(arr1, arr2):
 
        if not arr1 or not arr2:
            return False
            
        # If lengths of array are not
        # equal means array are not equal
        if len(arr1) != len(arr2):
            return False
    
        # Linearly compare elements
        for i in range(0, len(arr1) - 1):
            if (arr1[i] != arr2[i]):
                return False
    
        # If all elements were same.
        return True

def convert_string_to_array(string_to_convert:str, delimiter=' '):
    f = StringIO(string_to_convert)
    reader = csv.reader(f, delimiter=delimiter, quotechar='"')
    return_array = None
    for row in reader:
        return_array=row
    return return_array



class CommonBase(object):
    # Constructor
    def __init__(self,
                 on_start_handler,
                 on_stop_handler=None,
                 debug: bool = False):

        self.__running = False
        self._on_start_handler = on_start_handler
        self._on_stop_handler = on_stop_handler
        self._debug = debug

    def start(self):
        self.__running = True
        print('Running. Press CTRL-C to exit.')
        if self._on_start_handler:
            self._on_start_handler()
        # Tell Python to run the handler() function when SIGINT is recieved
        signal(SIGINT, self.exit_handler)
        signal(SIGTERM, self.exit_handler)
        while self.__running:
            # Do nothing and hog CPU forever until SIGINT received.
            time.sleep(1)
        print('Execution finished')
        sys.exit(0)

    def exit_handler(self, signal_received, frame):
        self.stop()

    def stop(self):
        if self._on_stop_handler:
            self._on_stop_handler()
        self.__running = False

    def is_running(self) -> bool:
        return self.__running
