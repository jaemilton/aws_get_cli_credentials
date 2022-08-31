#!/usr/bin/python3
# -*- coding: UTF-8 -*-

class CommonError(Exception):
    """Exception class from which every exception in this library will derive.
         It enables other projects using this library to catch all errors coming
         from the library with a single "except" statement
    """
    pass


class BadUserInputError(CommonError):
    """A specific error"""
    pass
