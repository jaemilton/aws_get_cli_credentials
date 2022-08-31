from common_lib.common_base import valid_mandatory_parameters,get_input_parameter_value
from common_lib.common_error import BadUserInputError
from common_lib.aws_sso_login import AwsSsoLogin
from os.path import dirname, abspath
from dotenv import load_dotenv
import os, sys

path = dirname(abspath(__file__)) + '/.env'
load_dotenv(path)



def start(argv):
    if (('-h' in argv) or ('-?' in argv)):
        print("""
        python3 aws_configure_sso_accounts.py 
                        -url AWS_SSO_START_URL 
                        [-accounts_region AWS_ACCOUNTS_REGION] 
                        [-sso_region AWS_SSO_REGION] 
                        [-a AWS_ACCOUNT_ID] 
                        [-n AWS_ACCOUNT_NAME_PROFILE] 
                        [-p AWS_PROFILE_NAME]
                        [-ssl_verify TRUE|FALSE|CA_FILE_PATH]
                        [-t AWS_SSO_TRANSITION_TIMEOUT]
                        [-debug True|False]
                        [-proxy PROXY] 
                        [-h|-?]
        Program to load a csv to a mysql table
        Parameters:
            -url AWS_SSO_START_URL --> mandatory
            -accounts_region AWS_ACCOUNTS_REGION --> optional, if not set will assume sa-east-1
            -sso_region AWS_SSO_REGION --> optional, if not set will assume us-east-1
            -a AWS_ACCOUNT_ID --> optional, if set, only this account will have the credentials updated
            -n AWS_ACCOUNT_PROFILE_NAME --> optional, if set, only this account and profile "{aws_account_name}_{aws_account_role_name}" will have the credentials updated
            -p AWS_PROFILE_NAME --> Optional, replace de profile name, if not set, the profilename will be "{aws_account_name}_{aws_account_role_name}"
            -d DEFAULT_PROFILE_NAME --> Optional, profile name with must credentials set as default profile
            -ssl_verify TRUE|FALSE|CA_FILE_PATH --> Optional, if not set will be True
            -t AWS_SSO_TRANSITION_TIMEOUT --> Optional, if not set will be 60 seconds
            -debug True|False --> Optional, if not set will be False
            -proxy PROXY--> optional

            For execution, it requires the following environment variables set
            - AWS_USERNAME
            - AWS_PASSWORD
            - EDGE_DRIVER_PATH
            - OTP_2FA_DEVICE_ID, if it is necessary for aws logon

            -h or -? help
        """)
    
    elif not valid_mandatory_parameters(argv, ['-url']):
        raise BadUserInputError(
            """Input error. To run, python3 aws_configure_sso_accounts.py -url AWS_SSO_START_URL 
                                                                        [-accounts_region AWS_ACCOUNTS_REGION] 
                                                                        [-sso_region AWS_SSO_REGION] 
                                                                        [-a AWS_ACCOUNT_ID] 
                                                                        [-n AWS_ACCOUNT_NAME] 
                                                                        [-p AWS_PROFILE_NAME]
                                                                        [-ssl_verify TRUE|FALSE|CA_FILE_PATH]
                                                                        [-t AWS_SSO_TRANSITION_TIMEOUT]
                                                                        [-debug True|False]
                                                                        [-proxy PROXY] 
                                                                        [-h|-?]""")

    else:
        aws_sso_start_url:str = get_input_parameter_value(argv,'-url')
        aws_username:str = None if "AWS_USERNAME" not in os.environ else os.environ["AWS_USERNAME"]
        if aws_username is None:
            raise BadUserInputError("The environment variable AWS_USERNAME not found")

        aws_password:str = None if "AWS_PASSWORD" not in os.environ else os.environ["AWS_PASSWORD"]
        if aws_password is None:
            raise BadUserInputError("The environment variable AWS_PASSWORD not found")

        if "EDGE_DRIVER_PATH" not in os.environ :
            raise BadUserInputError("The environment variable EDGE_DRIVER_PATH not found")

        aws_account_id = get_input_parameter_value(argv,'-a')
        aws_account_profile_name = get_input_parameter_value(argv,'-n')
        aws_default_account_profile_name = get_input_parameter_value(argv,'-d')

        aws_accounts_default_region_param = get_input_parameter_value(argv,'-accounts_region')
        aws_accounts_default_region = aws_accounts_default_region_param if aws_accounts_default_region_param is not None else "sa-east-1"

        aws_sso_region_param = get_input_parameter_value(argv,'-sso_region')
        aws_sso_region = aws_sso_region_param if aws_sso_region_param is not None else "us-east-1"

        custom_aws_profile_name = get_input_parameter_value(argv,'-p')

        otp_2fa_devide_id = None if "OTP_2FA_DEVICE_ID" not in os.environ else os.environ["OTP_2FA_DEVICE_ID"]
        proxy = get_input_parameter_value(argv,'-proxy')
        
        selenium_aws_sso_transition_timeout_param = get_input_parameter_value(argv,'-t')
        selenium_aws_sso_transition_timeout = 60 if selenium_aws_sso_transition_timeout_param is None else int(selenium_aws_sso_transition_timeout_param)


        debug_param = get_input_parameter_value(argv,'-debug')
        debug = False if debug_param is None else bool(debug_param)

        ssl_verify_param:str = get_input_parameter_value(argv,'-ssl_verify')

        if ssl_verify_param is None or ssl_verify_param.lower() == 'true':
            ssl_verify = True
        elif ssl_verify_param.lower() == 'false':
            ssl_verify = False
        else:
            ssl_verify = ssl_verify_param

        aws_sso_login = AwsSsoLogin(aws_sso_start_url=aws_sso_start_url,
                                    aws_sso_region=aws_sso_region,
                                    aws_accounts_default_region=aws_accounts_default_region,
                                    aws_username=aws_username,
                                    aws_password=aws_password,
                                    otp_2fa_devide_id=otp_2fa_devide_id,
                                    aws_account_id=aws_account_id,
                                    aws_account_profile_name=aws_account_profile_name,
                                    custom_aws_profile_name=custom_aws_profile_name,
                                    aws_default_account_profile_name = aws_default_account_profile_name,
                                    proxy=proxy,
                                    ssl_verify=ssl_verify,
                                    selenium_aws_sso_transition_timeout=selenium_aws_sso_transition_timeout,
                                    debug=debug)
        aws_sso_login.start()
start(sys.argv)
