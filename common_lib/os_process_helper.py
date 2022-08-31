#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from subprocess import Popen
from threading import Thread
from common_lib.common_error import BadUserInputError
import time, csv, psutil, os
from datetime import datetime
from psutil import NoSuchProcess

class OsProcessHelper(object):
    """
    Call in a loop to create terminal progress bar
    @params:
        command       - Required  : command
        args       - Optional  : with interation number is the start interation
    """

    def __init__(self, 
                    command:str,
                    args:str) -> None:
        self.command = command
        self.args = args
        self.monitoring_data = []
        self.max_cpu_percentage=0
        self.max_memory=0

    def start(self):
        command_params = [self.command]
        command_params.extend(self.args)
        self.process_info = Popen(command_params)
        self.process = psutil.Process(self.process_info.pid)
        self.thread = Thread(target=self.monitor_process)
        self.thread.start()
        
    def monitor_process(self):
        while self.process.is_running():
            try:
                mem = self.process.memory_info()
                cpu = self.process.cpu_percent(interval=1.0)
                used_memory = mem.vms / 1024 / 1024 
                self.max_cpu_percentage=max(self.max_cpu_percentage, cpu)
                self.max_memory=max(self.max_memory, used_memory)
                self.monitoring_data.append([datetime.now(), cpu, used_memory])
            except NoSuchProcess:
                pass
            
    def wait(self):
        return self.process_info.wait()

    def get_pid(self):
        return self.process_info.pid

    def write_process_monitoring_data_csv(self, csv_path:str):

        if os.path.exists(csv_path):
            raise BadUserInputError(
                f"ERROR: The file {csv_path} alread exists")

        directory = os.path.dirname(csv_path)
        if not os.path.exists(directory):
            csv_path = os.path.join(os.getcwd(), csv_path)

        with open(csv_path, mode='w', newline='') as f:
            writer = csv.writer(f,  delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            for data in self.monitoring_data:
                writer.writerow(data)
            
    def get_param_by_name(self, name:str)-> str:
        index = self.args.index(name)
        value = None
        try:
            value = self.args[index + 1]
        except Exception:
            pass

        return value

