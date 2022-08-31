from common_lib.otp_helper import OtpHelper
from common_lib.common_base import get_input_parameter_value, valid_mandatory_parameters
from common_lib.common_error import BadUserInputError
import sys


def start(argv):
    if (('-h' in argv) or ('-?' in argv)):
        print("""
        python3 get_token.py -d DEVICE_ID [-h|-?]
        Program to load a csv to a mysql table
        Parameters:
            -d DEVICE_ID  --> mandatory
            -h or -? help
        """)
    
    elif not valid_mandatory_parameters(argv, ['-d']):
        raise BadUserInputError(
            "Input error. To run, call as python3 get_token.py -d DEVICE_ID [-h|-?]")

    else:
        otp_device_id:str = get_input_parameter_value(argv,'-d')

        otp_helper = OtpHelper(otp_device_id)
        print(otp_helper.get_code())

start(sys.argv)
