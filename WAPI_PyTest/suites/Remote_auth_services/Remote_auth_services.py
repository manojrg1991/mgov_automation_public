__author__ = "Aditya G"
__email__  = "adityag@infoblox.com"

########################################################################################
#  Grid Set up required:                                                               #
#  1. SA Grid Master                                                                   #
#  2. Licenses : DNS, DHCP, Grid, NIOS (IB-V1425)                                      #
########################################################################################


import config
import pytest
import unittest
import logging
import json
import os
import re
import sys
import ib_utils.ib_NIOS as ib_NIOS
import ib_utils.common_utilities as ib_TOKEN
from ib_utils.start_stop_logs import log_action as log
from ib_utils.file_content_validation import log_validation as logv
from time import sleep
import pexpect
import subprocess
import ib_utils.common_utilities as common_util

logging.basicConfig(filename='cas.log', filemode='w', level=logging.DEBUG)

def display_msg(msg):
    print(msg)
    logging.info(msg)

def map_remote_user_to_the_group(group='admin-group'):
    display_msg("Selecting remote user to be mapped to the group "+group)
    response = ib_NIOS.wapi_request("GET",object_type="authpolicy")
    auth_policy_ref = json.loads(response)[0]['_ref']
    data={"default_group": group}
    response = ib_NIOS.wapi_request('PUT', ref=auth_policy_ref, fields=json.dumps(data), grid_vip=config.grid_vip)
    display_msg(response)
    if bool(re.match("\"authpolicy*.",str(response))):
        display_msg("Selected '"+group+"' for remote user mapping successfully")
        assert True
    else:
        display_msg("Selecting '"+group+"' for remote user mapping failed")
        assert False

def dras_requests():
    """
    Perform dras command
    """
    print("sending dras")
    dras_cmd = 'sudo /import/tools/qa/tools/dras/dras -i ' +str(config.grid1_master_vip)+ ' -q 5 -R 5 -t 10000 -n 1 -h -a B1:11:20:00:00:D0 -r'
    print(dras_cmd)
    dras_cmd1 = os.system(dras_cmd)
    print (dras_cmd1)


class CAS(unittest.TestCase):

    @pytest.mark.run(order=1)
    def test_001_Check_if_RADIUS_service_is_up_and_running_on_the_authentication_server_else_start_the_service(self):
        display_msg("Checking if the RADIUS service is up and running on the authentication server, else, start the service")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.auth_server,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the auth server, please check connectivity to the auth server")
            assert False
        else:
            child.expect("password:")
            child.sendline("Infoblox#123")
            child.expect(" ~]#")
            child.sendline("ps ax|grep radius")
            output = child.before
            child.expect(" ~]#")
            output = child.before
            print(output)
            output = re.sub(r'\x1b\[([0-9,A-Z]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?', '', output)
            print(output.split())
            if '/usr/sbin/radiusd' in output:
                display_msg("Radius service is running on the auth server")
                child.close()
                assert True
            else:
                display_msg("Radius service is not running on the auth server, proceeding further to start the radius service")
                try:
                    child.sendline("service radiusd start")
                except pexpect.ExceptionPexpect as error:
                    display_msg("Unable to start radius service")
                    display_msg(error)
                    assert False
                else:
                    sleep(20)
                    child.expect(" ~]#")
                    child.sendline("service radiusd status --no-pager")
                    output = child.before
                    child.expect(" ~]#")
                    output = child.before
                    print(output)
                    if 'active (running)' in output:
                        display_msg("Radius service running successfully")
                        child.close()
                        assert True
                    else:
                        display_msg("Radius service status is not active, please check the below output and debug")
                        display_msg(output)
                        child.close()
                        assert False


    
    @pytest.mark.run(order=2)
    def test_002_Check_if_TACACS_service_is_up_and_running_on_the_authentication_server_else_start_the_service(self):
        display_msg("Checking if the TACACS service is up and running on the authentication server, else, start the service")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.auth_server,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the auth server, please check connectivity to the auth server")
            assert False
        else:
            child.expect("password:")
            child.sendline("Infoblox#123")
            child.expect(" ~]#")
            child.sendline("ps ax|grep tac")
            output = child.before
            child.expect(" ~]#")
            output = child.before
            print(output)
            output = re.sub(r'\x1b\[([0-9,A-Z]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?', '', output)
            print(output.split())
            if '/usr/bin/tac_plus' in output:
                display_msg("TACACS service is running on the auth server")
                child.close()
                assert True
            else:
                display_msg("TACACS service is not running on the auth server, proceeding further to start the TACACS service")
                try:
                    child.sendline("/usr/bin/tac_plus -C /etc/tac_plus.conf -d 16 -l /root/tacacs.log")
                except pexpect.ExceptionPexpect as error:
                    display_msg("Unable to start TACACS service")
                    display_msg(error)
                    assert False
                else:
                    sleep(20)
                    child.expect(" ~]#")
                    child.sendline("ps ax|grep tac")
                    output = child.before
                    child.expect(" ~]#")
                    output = child.before
                    print(output)
                    output = re.sub(r'\x1b\[([0-9,A-Z]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?', '', output)
                    if '/usr/bin/tac_plus' in output:
                        display_msg("TACACS service running successfully")
                        child.close()
                        assert True
                    else:
                        display_msg("TACACS service status is not active, please check the below output and debug")
                        display_msg(output)
                        child.close()
                        assert False



    
    @pytest.mark.run(order=3)
    def test_003_Check_if_LDAP_service_is_up_and_running_on_the_authentication_server_else_start_the_service(self):
        display_msg("Checking if the LDAP service is up and running on the authentication server, else, start the service")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.auth_server,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the auth server, please check connectivity to the auth server")
            assert False
        else:
            child.expect("password:")
            child.sendline("Infoblox#123")
            child.expect(" ~]#")
            child.sendline("ps ax|grep slapd")
            output = child.before
            child.expect(" ~]#")
            output = child.before
            print(output)
            output = re.sub(r'\x1b\[([0-9,A-Z]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?', '', output)
            print(output.split())
            if '/usr/sbin/slapd' in output:
                display_msg("LDAP service is running on the auth server")
                child.close()
                assert True
            else:
                display_msg("LDAP service is not running on the auth server, proceeding further to start the LDAP service")
                try:
                    child.sendline("systemctl start slapd")
                except pexpect.ExceptionPexpect as error:
                    display_msg("Unable to start ldap service")
                    display_msg(error)
                    assert False
                else:
                    sleep(20)
                    child.expect(" ~]#")
                    child.sendline("service slapd status --no-pager")
                    output = child.before
                    child.expect(" ~]#")
                    output = child.before
                    print(output)
                    if 'active (running)' in output:
                        display_msg("LDAP service running successfully")
                        child.close()
                        assert True
                    else:
                        display_msg("LDAP service status is not active, please check the below output and debug")
                        display_msg(output)
                        child.close()
                        assert False

    @pytest.mark.run(order=4)
    def test_004_Check_if_AD_server_is_reachable(self):
        display_msg("Check if AD server is reachable")
        try:
            subprocess.check_output(["ping", "-c", "5", config.ad_ip])
        except subprocess.CalledProcessError:
            display_msg("AD server is not rechable, contact the lab team to power it on")
            assert False
        else:
            display_msg("AD server is reachable")
            assert True

    

    @pytest.mark.run(order=5)
    def test_005_Create_a_non_super_user_group(self):
        display_msg("Creating a non super user group")
        data={"name":"non-superuser","access_method": ["API","CLI"]}
        response = ib_NIOS.wapi_request('POST',object_type="admingroup",fields=json.dumps(data))
        display_msg(response)
        if bool(re.match("\"admingroup*.",str(response))):
            display_msg("Group 'non-superuser' created successfully")
            assert True
        else:
            display_msg("Group 'non-superuser' creation unsuccessful")
            assert False


    @pytest.mark.run(order=6)
    def test_006_Create_a_group_named_infobloxgroup(self):
        display_msg("Creating a group named 'infobloxgroup'")
        data={"name":"infobloxgroup","superuser":True}
        response = ib_NIOS.wapi_request('POST',object_type="admingroup",fields=json.dumps(data))
        display_msg(response)
        if bool(re.match("\"admingroup*.",str(response))):
            display_msg("Group 'infobloxgroup' created successfully")
            assert True
        else:
            display_msg("Group 'infobloxgroup' creation unsuccessful")
            assert False



    @pytest.mark.run(order=7)
    def test_007_Create_a_group_named_asmgroup(self):
        display_msg("Creating a group named 'asmgroup'")
        data={"name":"asmgroup","superuser":True}
        response = ib_NIOS.wapi_request('POST',object_type="admingroup",fields=json.dumps(data))
        display_msg(response)
        if bool(re.match("\"admingroup*.",str(response))):
            display_msg("Group 'asmgroup' created successfully")
            assert True
        else:
            display_msg("Group 'asmgroup' creation unsuccessful")
            assert False


    @pytest.mark.run(order=8)
    def test_008_Configure_RADIUS_server_details_in_the_grid(self):
        display_msg("Configuring RADIUS server details in the grid")
        data={
                "name": "radius",
                "servers": [
                    {
                        "address": config.auth_server,
                        "auth_port": 1812,
                        "auth_type": "PAP",
                        "shared_secret": "testing123",
                        "use_accounting": False
                    }
                ]
            }
        response = ib_NIOS.wapi_request('POST', object_type="radius:authservice",fields=json.dumps(data))
        display_msg(response)
        if bool(re.match("\"radius:authservice*.",str(response))):
            display_msg("RADIUS service configured sucessfully")
            assert True
        else:
            display_msg("RADIUS service configuration failed")
            assert False

    @pytest.mark.run(order=9)
    def test_009_Configure_TACACS_server_details_in_the_grid(self):
        display_msg("Configuring TACACS server details in the grid")
        data={
                "name": "tacacs",
                "servers": [
                    {
                        "address": config.auth_server,
                        "shared_secret": "testing123"
                    }
                ]
            }
        response = ib_NIOS.wapi_request('POST', object_type="tacacsplus:authservice",fields=json.dumps(data))
        display_msg(response)
        if bool(re.match("\"tacacsplus:authservice*.",str(response))):
            display_msg("TACACS service configured sucessfully")
            assert True
        else:
            display_msg("TACACS service configuration failed")
            assert False



    @pytest.mark.run(order=10)
    def test_010_Configure_LDAP_server_details_in_the_grid(self):
        display_msg("Configuring LDAP server details in the grid")
        data={
                "name": "ldap",
                "servers": [
                {
                    "address": config.auth_server,
                    "version": "V3",
                    "base_dn": "dc=ldapserver,dc=local",
                    "authentication_type": "ANONYMOUS",
                    "encryption": "NONE",
                    "port": 389,
                    }],
                "ldap_group_authentication_type": "GROUP_ATTRIBUTE",
                "search_scope": "SUBTREE",
                "ldap_user_attribute": "uid",
                "timeout": 5,
                "retries":5,
                "recovery_interval":30
            }

        response = ib_NIOS.wapi_request('POST', object_type="ldap_auth_service",fields=json.dumps(data))
        display_msg(response)
        if bool(re.match("\"ldap_auth_service*.",str(response))):
            display_msg("LDAP service configured sucessfully")
            assert True
        else:
            display_msg("LDAP service configuration failed")
            assert False




    @pytest.mark.run(order=11)
    def test_011_Configure_AD_server_details_in_the_grid(self):
        display_msg("Configuring AD server details in the grid")
        data={
                "name": "adserver",
                "ad_domain": config.ad_domain,
                "domain_controllers": [
                    {
                        "auth_port": 389,
                        "disabled": False,
                        "fqdn_or_ip": config.ad_ip,
                        "encryption": "NONE",
                        "use_mgmt_port": False
                    }
                ]
            }
        response = ib_NIOS.wapi_request('POST', object_type="ad_auth_service",fields=json.dumps(data))
        display_msg(response)
        if bool(re.match("\"ad_auth_service*.",str(response))):
            display_msg("AD service configured sucessfully")
            assert True
        else:
            display_msg("AD service configuration failed")
            assert False


    @pytest.mark.run(order=12)
    def test_012_Add_RADIUS_TACACS_LDAP_AD_to_the_Authentication_Policy_list(self):
        display_msg("Adding RADIUS, TACACS, LDAP and AD service to the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS, LDAP and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ldap_ref,ad_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False



    @pytest.mark.run(order=13)
    def test_013_Assign_remote_users_admin_group_as_superuser(self):
        map_remote_user_to_the_group()

    
    @pytest.mark.run(order=14)
    def test_014_Login_to_the_grid_using_RADIUS_credentials_as_superuser_and_execute_cli_command(self):
        display_msg("Logging into the grid using RADIUS credentials via CLI as a superuser")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.radius_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.radius_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            display_msg(output)
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=15)
    def test_015_Verify_logs_for_RADIUS_user_login_as_superuser(self):
        display_msg("Verify logs for RADIUS user login as superuser")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info RADIUS authentication succeeded for user "+config.radius_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*Successfully authenticated NIOS superuser '"+config.radius_username+"'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.radius_username+".*auth=RADIUS.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False



    @pytest.mark.run(order=16)
    def test_016_Assign_remote_users_admin_group_as_non_superuser(self):
        map_remote_user_to_the_group('non-superuser')

    
    @pytest.mark.run(order=17)
    def test_017_Login_to_the_grid_using_RADIUS_credentials_as_non_superuser_and_execute_cli_command(self):
        display_msg("Logging into the grid using RADIUS credentials via CLI as a non-superuser")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.radius_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.radius_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            child.close()
            if 'Error: The user does not have sufficient privileges to run this command' in output:
                display_msg("The user was not able to execute command as a super user")
                assert True
            else:
                display_msg("The user was able to execute command as a super user")
                assert False


    @pytest.mark.run(order=18)
    def test_018_Verify_logs_for_radius_user_login_as_non_superuser(self):
        display_msg("Verify logs for radius user login as non-superuser")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info RADIUS authentication succeeded for user "+config.radius_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*Successfully authenticated NIOS superuser '"+config.radius_username+"'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.radius_username+".*auth=RADIUS.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            map_remote_user_to_the_group()
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            map_remote_user_to_the_group()
            assert False

    
    @pytest.mark.run(order=19)
    def test_019_Remove_Radius_from_the_Authentication_Policy_list(self):
        display_msg("Remove Radius service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        '''display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)'''


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)

        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Add Local, AD, TACACS and LDAP to the authentiation policy list")
        data={"auth_services":[local_user_ref,ad_ref,tacacs_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, AD, TACACS and LDAP added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, AD, TACACS and LDAP addition to the authentiation policy list failed")
            assert False

    @pytest.mark.run(order=20)
    def test_020_Configure_RADIUS_server_details_with_acc_mgmt_port_enabled_in_the_grid(self):
        display_msg("Configuring RADIUS server details with accounting and mgmt port enabled in the grid")
        response = ib_NIOS.wapi_request("GET",object_type="radius:authservice")
        print(response)
        ref_radius = json.loads(response)[0]['_ref']
        print("\n")
        print(ref_radius)
        data={
                "name": "radius",
                "servers": [
                    {
                        "address": config.auth_server,
                        "auth_port": 1812,
                        "auth_type": "PAP",
                        "shared_secret": "testing123",
                        "use_accounting": True,
                        "use_mgmt_port": True
                    }
                ]
            }
        response = ib_NIOS.wapi_request('PUT', ref=ref_radius,fields=json.dumps(data))
        display_msg(response)
        if bool(re.match("\"radius:authservice*.",str(response))):
            display_msg("AD service configured sucessfully")
            assert True
        else:
            display_msg("AD service configuration failed")
            assert False
        display_msg("Test case 20 Execution Completed")

    
    @pytest.mark.run(order=21)
    def test_021_Add_Radius_to_the_Authentication_Policy_list(self):
        display_msg("Add Radius service to the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS, LDAP and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False

    
    @pytest.mark.run(order=22)
    def test_022_Capture_Tcpdump_for_accounting_radius(self):

        display_msg("Capture Tcpdump logs for radius accounting")

        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('#')
        child.sendline('nohup tcpdump -i any -n port 1813 -c 2 > tee.txt &')
        child.expect('')
        child.sendline('\n')
        child.expect('#')
        child.close()

        display_msg("Test case 22 Execution Completed")

    @pytest.mark.run(order=23) 
    def test_023_verify_radius_gui_login(self):
        print("Testcase 23 started")
        output = os.popen("curl -k -u user1_radius:infoblox -H 'Content-type: application/json' -X GET https://"+config.grid_vip+"/wapi/v"+config.wapi_version+"/grid").read()
        print(output)
        if "401 Authorization Required" in output:
             assert False
        sleep(10)
	print("Test Case 18 Execution Completed")

    '''
    @pytest.mark.run(order=23)
    def test_023_Login_SSH_radius_user(self):

        display_msg("Logging into the grid using RADIUS credentials with accounting")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.radius_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
            child.close()
        else:
            child.expect("password:")
            child.sendline(config.radius_password)
            child.expect("Infoblox >")
            child.close()
        display_msg("Test case 23 Execution Completed")
	sleep(5)
    '''

    @pytest.mark.run(order=24)
    def test_024_validate_radius_accounting_tcpdump(self):

        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('#')
        child.sendline('ls -lrt')
        child.expect('#')
        child.sendline('cat tee.txt')
        child.expect('#')
        output = child.before
        print("#####OUTPUT#####",output)
        if re.search(r".*10.197.38.101.1813.*Accounting-Response.*",output):
            assert True
            child.close()
        else:
            assert False
            child.close()
	sleep(10)
        display_msg("Test case 24 Execution Completed")

    @pytest.mark.run(order=25)
    def test_025_validate_radius_mgmt_interface_tcpdump(self):

        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('#')
        child.sendline('ls -lrt')
        child.expect('#')
        output = child.before
        child.sendline('cat tee.txt')
        child.expect('#')
        output = child.before
        print("#####OUTPUT#####",output)
        child.sendline("killall tcpdump")
        child.expect("#")        
	if re.search(r".*"+config.grid_vip+".*Accounting-Response.*",output):
	#if re.search('(.+)'+config.grid_vip+'(.*"+config.auth_server+".1813.*)',output):
            assert True
            child.close()
        else:
            assert False
            child.close()
	sleep(10)
        display_msg("Test case 25 Execution Completed")

    '''
    @pytest.mark.run(order=26)
    def test_026_Kill_process(self):

        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('#')

        child.sendline("killall tcpdump")
        child.expect("#")
        output = child.before
        print("$$$$$$$$$$$$$",output)  

        display_msg("Test case 26 Execution Completed")
    ''' 

    @pytest.mark.run(order=27)
    def test_027_Assign_remote_users_admin_group_as_superuser(self):
        map_remote_user_to_the_group('infobloxgroup')

    
    @pytest.mark.run(order=28)
    def test_028_Login_to_the_grid_using_TACACS_credentials_as_superuser_and_execute_cli_command(self):
        display_msg("Logging into the grid using TACACS credentials via CLI as a superuser")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.tacacs_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.tacacs_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=29)
    def test_029_Verify_logs_for_TACACS_user_login_as_superuser(self):
        display_msg("Verify logs for TACACS user login as superuser")

        display_msg("Stopping log capture")
        sleep(20)

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info TACACS\+ authentication succeeded for user "+config.tacacs_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*Successfully authenticated NIOS superuser '"+config.tacacs_username+"'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.tacacs_username+".*auth=TACACS+.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=30)
    def test_030_Change_infobloxgroup_from_superuser_to_nonsuperuser_group(self):
        display_msg("Change the infobloxgroup from super user to non superuser")
        display_msg("Fetching infobloxgroup reference")
        response = ib_NIOS.wapi_request("GET",object_type="admingroup")
        group_ref=''
        for ref in json.loads(response):
            if ref['name'] == 'infobloxgroup':
                group_ref = ref['_ref']
                break
        if group_ref == '':
            display_msg("infoblox group not found")
            assert False
        data={"superuser":False,"access_method": ["API","CLI"]}
        display_msg("Changing the infobloxgroup to nonsuperuser group")
        response = ib_NIOS.wapi_request('PUT', ref=group_ref, fields=json.dumps(data), grid_vip=config.grid_vip)
        display_msg(response)
        if bool(re.match("\"admingroup*.",str(response))):
            display_msg("Changed the infobloxgroup from superuser to nonsuperuser group successfully")
            sleep(10)
            assert True
        else:
            display_msg("Changing the infobloxgroup from superuser to nonsuperuser group failed")
            assert False

    


    @pytest.mark.run(order=31)
    def test_031_Assign_remote_users_admin_group_as_non_superuser(self):
        map_remote_user_to_the_group('infobloxgroup')

    
    @pytest.mark.run(order=32)
    def test_032_Login_to_the_grid_using_TACACS_credentials_as_non_superuser_and_execute_cli_command(self):
        display_msg("Logging into the grid using TACACS credentials via CLI as a non-superuser")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.tacacs_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.tacacs_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            child.close()
            if 'Error: The user does not have sufficient privileges to run this command' in output:
                display_msg("The user was not able to execute command as a super user")
                assert True
            else:
                display_msg("The user was able to execute command as a super user")
                assert False


    @pytest.mark.run(order=33)
    def test_033_Verify_logs_for_TACACS_user_login_as_non_superuser(self):
        display_msg("Verify logs for TACACS user login as non-superuser")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info TACACS\+ authentication succeeded for user "+config.tacacs_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*Successfully authenticated NIOS superuser '"+config.tacacs_username+"'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.tacacs_username+".*auth=TACACS+.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=34)
    def test_034_Remove_TACACS_from_the_Authentication_Policy_list(self):
        display_msg("Remove TACACS service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        '''display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)'''

        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Add Local, AD, Radius and LDAP to the authentiation policy list")
        data={"auth_services":[local_user_ref,ad_ref,radius_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, AD, Radius and LDAP added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, AD, Radius and LDAP addition to the authentiation policy list failed")
            assert False

    @pytest.mark.run(order=35)
    def test_035_Configure_TACACS_server_details_with_acc_mgmt_port_enabled_in_the_grid(self):
        display_msg("Configuring TACACS server details with accounting and mgmt port enabled in the grid")
        response = ib_NIOS.wapi_request("GET",object_type="tacacsplus:authservice")
        print(response)
        ref_tacacs = json.loads(response)[0]['_ref']
        print("\n")
        print(ref_tacacs)
        data={
                "name": "tacacs",
                "servers": [
                    {
                        "address": config.auth_server,
                        "shared_secret": "testing123",
                        "use_accounting": True,
                        "use_mgmt_port": True
                    }
                ]
            }
        response = ib_NIOS.wapi_request('PUT', ref=ref_tacacs,fields=json.dumps(data))
        display_msg(response)
        if bool(re.match("\"tacacsplus:authservice*.",str(response))):
            display_msg("TACACS service configured sucessfully")
            assert True
        else:
            display_msg("TACACS service configuration failed")
            assert False
        display_msg("Test case 89 Execution Completed")


    
    @pytest.mark.run(order=36)
    def test_036_Add_TACACS_to_the_Authentication_Policy_list(self):
        display_msg("Add Radius service to the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS, LDAP and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False


    @pytest.mark.run(order=37)
    def test_037_Capture_Tcpdump_for_accounting_tacacs(self):

        display_msg("Capture Tcpdump logs for radius accounting")

        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('#')
        child.sendline('nohup tcpdump -i any -n port 49 -c 5 > tee.txt &')
        child.expect('')
        child.sendline('\n')
        child.expect('#')
        child.close()
        display_msg("Test case 96 Execution Completed")

    @pytest.mark.run(order=38)
    def test_038_Login_SSH_tacacs_user(self):

        display_msg("Logging into the grid using TACACS credentials with accounting")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.tacacs_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
            child.close()
        else:
            child.expect("password:")
            child.sendline(config.tacacs_password)
            child.expect("Infoblox >")
            child.close()

        display_msg("Test case 97 Execution Completed")
	sleep(5)

    @pytest.mark.run(order=39)
    def test_039_validate_tacacs_accounting_tcpdump(self):

        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('#')
        child.sendline('ls -lrt')
        child.expect('#')
        child.sendline('cat tee.txt')
        child.expect('#')
        output = child.before
        print("#####OUTPUT#####",output)
        if re.search(r".*"+config.auth_server+".49.*",output):
	#if re.search(r".*"+config.auth_server+".49.*",output):
            assert True
            child.close()
        else:
            assert False
            child.close()

        display_msg("Test case 98 Execution Completed")


    @pytest.mark.run(order=40)
    def test_040_validate_tacacs_mgmt_interface_tcpdump(self):

        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('#')
        child.sendline('ls -lrt')
        child.expect('#')
        output = child.before
        child.sendline('cat tee.txt')
        child.expect('#')
        output = child.before
        print("#####OUTPUT#####",output)
        if re.search(r".*"+config.grid_vip+".*"+config.auth_server+".49.*",output):
	#if re.search('(.+)'+config.grid_vip+'(.*"+config.auth_server+".49.*)',output):
            assert True
            child.close()
        else:
            assert False
            child.close()

        display_msg("Test case 99 Execution Completed")



    @pytest.mark.run(order=41)
    def test_041_Assign_remote_users_admin_group_as_superuser(self):
        map_remote_user_to_the_group('asmgroup')
        sleep(5)

    
    @pytest.mark.run(order=42)
    def test_042_Login_to_the_grid_using_AD_credentials_as_superuser_and_execute_cli_command(self):
        display_msg("Logging into the grid using AD credentials via CLI as a superuser")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ad_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ad_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=43)
    def test_043_Verify_logs_for_AD_user_login_as_superuser(self):
        display_msg("Verify logs for AD user login as superuser")

        display_msg("Stopping log capture")
        sleep(20)

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info AD authentication succeeded for user "+config.ad_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*"+config.ad_username+".*AD Authentication Succeeded.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ad_username+".*auth=Active.*Directory.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=44)
    def test_044_Change_asmgroup_from_superuser_to_nonsuperuser_group(self):
        display_msg("Change the asmgroup from super user to non superuser")
        display_msg("Fetching asmgroup reference")
        response = ib_NIOS.wapi_request("GET",object_type="admingroup")
        group_ref=''
        for ref in json.loads(response):
            if ref['name'] == 'asmgroup':
                group_ref = ref['_ref']
                break
        if group_ref == '':
            display_msg("asmgroup not found")
            assert False
        data={"superuser":False,"access_method": ["API","CLI"]}
        display_msg("Changing the asmgroup to nonsuperuser group")
        response = ib_NIOS.wapi_request('PUT', ref=group_ref, fields=json.dumps(data), grid_vip=config.grid_vip)
        display_msg(response)
        if bool(re.match("\"admingroup*.",str(response))):
            display_msg("Changed the asmgroup from superuser to nonsuperuser group successfully")
            assert True
            sleep(10)
        else:
            display_msg("Changing the asmgroup from superuser to nonsuperuser group failed")
            assert False




    @pytest.mark.run(order=45)
    def test_045_Assign_remote_users_admin_group_as_non_superuser(self):
        map_remote_user_to_the_group('asmgroup')

    
    @pytest.mark.run(order=46)
    def test_046_Login_to_the_grid_using_AD_credentials_as_non_superuser_and_execute_cli_command(self):
        display_msg("Logging into the grid using AD credentials via CLI as a non-superuser")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ad_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ad_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            child.close()
            if 'Error: The user does not have sufficient privileges to run this command' in output:
                display_msg("The user was not able to execute command as a super user")
                assert True
            else:
                display_msg("The user was able to execute command as a super user")
                assert False


    @pytest.mark.run(order=47)
    def test_047_Verify_logs_for_AD_user_login_as_non_superuser(self):
        display_msg("Verify logs for AD user login as non-superuser")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info AD authentication succeeded for user "+config.ad_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*"+config.ad_username+".*AD Authentication Succeeded.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ad_username+".*auth=Active.*Directory.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            map_remote_user_to_the_group()
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            map_remote_user_to_the_group()
            assert False


    @pytest.mark.run(order=48)
    def test_048_Add_DNS_resolver(self):
        logging.info("Add DNS resolver")
        get_ref = ib_NIOS.wapi_request('GET', object_type="grid")
        grid_ref = json.loads(get_ref)[0]['_ref']
        data = {"dns_resolver_setting":{"resolvers":[config.resolver_ad],"search_domains": []}}
        resolver_ref = ib_NIOS.wapi_request('PUT', ref=grid_ref, fields=json.dumps(data))
        logging.info(resolver_ref)
        if bool(re.match("\"grid*.",str(resolver_ref))):
            logging.info("Resolver added successfully")
        else:
            raise Exception("DNS resolver update failed")

    @pytest.mark.run(order=49)
    def test_049_Upload_AD_CA_cert(self):
        dir_name="certificate/"
        base_filename="ad_ca_cert.cer"
        token = common_util.generate_token_from_file(dir_name,base_filename)
        print(token)
        data = {"token": token, "certificate_usage":"EAP_CA"}
        response = ib_NIOS.wapi_request('POST', object_type="fileop",fields=json.dumps(data),params="?_function=uploadcertificate")
        print(response)
        #Verify if certificate was uploaded
        get_ref = ib_NIOS.wapi_request('GET', object_type="cacertificate")
        ref_certs = json.loads(get_ref)
        count = 0
        for i in ref_certs:
            if i["distinguished_name"] == "CN=\"ad19181-WIN-5DCBLGU6LIH-CA-1\"":
                count +=1
        if count!= 0:
            print("AD CA certificate uploaded successfully")
            assert True
        else:
            print("AD CA certificate upload failed")
            assert False

    
    @pytest.mark.run(order=50)
    def test_050_Remove_AD_from_the_Authentication_Policy_list(self):
        display_msg("Remove AD service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Add Local, RADIUS, TACACS and LDAP to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS and LDAP added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS and LDAP addition to the authentiation policy list failed")
            assert False


    @pytest.mark.run(order=51)
    def test_051_Configure_AD_server_details_with_SSL_in_the_grid(self):
        response = ib_NIOS.wapi_request("GET",object_type="ad_auth_service")
        print(response)
        ref_ad = json.loads(response)[0]['_ref']
        print("\n")
        print(ref_ad)
        display_msg("Configuring AD server details with SSL in the grid")
        data={
                "name": "adserver",
                "ad_domain": config.ad_domain_ssl,
                "domain_controllers": [
                    {
                        "auth_port": 636,
                        "disabled": False,
                        "fqdn_or_ip": config.ad_fqdn,
                        "encryption": "SSL",
                        "use_mgmt_port": False
                    }
                ]
            }
        response = ib_NIOS.wapi_request('PUT', ref=ref_ad,fields=json.dumps(data))
        display_msg(response)
        if bool(re.match("\"ad_auth_service*.",str(response))):
            display_msg("AD service configured sucessfully")
            assert True
        else:
            display_msg("AD service configuration failed")
            assert False
    

    @pytest.mark.run(order=52)
    def test_052_Add_AD_to_the_Authentication_Policy_list(self):
        display_msg("Add AD service to the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS, LDAP and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False


    @pytest.mark.run(order=53)
    def test_053_Login_to_the_grid_using_AD_credentials_and_execute_cli_command(self):
        display_msg("Logging into the grid using AD credentials via CLI")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ad_username_ssl+'@'+config.grid_vip,timeout=30)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ad_pass_ssl)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            print(output)
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=54)
    def test_054_Verify_logs_for_AD_user_login(self):
        display_msg("Verify logs for AD user login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*AD authentication succeeded for user "+config.ad_username_ssl+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*AD Authentication Succeeded.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ad_username_ssl+".*Login_Allowed.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=55)
    def test_055_Login_to_the_grid_using_invalid_credentials_and_check_if_AD_authentication_fails(self):
        display_msg("Logging into the grid using invalid AD credentials and check if login fails")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no invalid@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ad_pass_ssl)
            child.expect("password:")
            output = child.before
            print(output)
            child.close()
            if 'Permission denied, please try again' in output:
                display_msg("Login to the grid using invalid LDAP credentials failed as expected")
                assert True
            else:
                display_msg("Login using invalid LDAP credentials passed")
                assert False


    @pytest.mark.run(order=56)
    def test_056_Verify_logs_for_failed_AD_user_login(self):
        display_msg("Verify logs for AD user failed login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*AD authentication for user invalid failed.*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*AD authentication for user invalid failed.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*Login_Denied.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False



    @pytest.mark.run(order=57)
    def test_057_Remove_AD_from_the_Authentication_Policy_list(self):
        display_msg("Remove AD service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Add Local, RADIUS, TACACS and LDAP to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS and LDAP added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS and LDAP addition to the authentiation policy list failed")
            assert False


    @pytest.mark.run(order=58)
    def test_058_Configure_AD_server_details_with_mgmt_port_in_the_grid(self):
        response = ib_NIOS.wapi_request("GET",object_type="ad_auth_service")
        print(response)
        ref_ad = json.loads(response)[0]['_ref']
        print("\n")
        print(ref_ad)
        display_msg("Configuring AD server details with mgmt port in the grid")
        data={
                "name": "adserver",
                "ad_domain": config.ad_domain_ssl,
                "domain_controllers": [
                    {
                        "auth_port": 636,
                        "disabled": False,
                        "fqdn_or_ip": config.ad_fqdn,
                        "encryption": "SSL",
                        "use_mgmt_port": True
                    }
                ]
            }
        response = ib_NIOS.wapi_request('PUT', ref=ref_ad,fields=json.dumps(data))
        display_msg(response)
        if bool(re.match("\"ad_auth_service*.",str(response))):
            display_msg("AD service configured sucessfully")
            assert True
        else:
            display_msg("AD service configuration failed")
            assert False
    

    @pytest.mark.run(order=59)
    def test_059_Add_AD_to_the_Authentication_Policy_list(self):
        display_msg("Add AD service to the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS, LDAP and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False


    @pytest.mark.run(order=60)
    def test_060_Login_to_the_grid_using_AD_credentials_and_execute_cli_command(self):
        display_msg("Logging into the grid using AD credentials via CLI")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ad_username_ssl+'@'+config.grid_vip,timeout=30)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ad_pass_ssl)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            print(output)
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=61)
    def test_061_Verify_logs_for_AD_user_login(self):
        display_msg("Verify logs for AD user login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*AD authentication succeeded for user "+config.ad_username_ssl+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*AD Authentication Succeeded.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ad_username_ssl+".*Login_Allowed.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=62)
    def test_062_Login_to_the_grid_using_invalid_credentials_and_check_if_AD_authentication_fails(self):
        display_msg("Logging into the grid using invalid AD credentials and check if login fails")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no invalid@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ad_pass_ssl)
            child.expect("password:")
            output = child.before
            print(output)
            child.close()
            if 'Permission denied, please try again' in output:
                display_msg("Login to the grid using invalid LDAP credentials failed as expected")
                assert True
            else:
                display_msg("Login using invalid LDAP credentials passed")
                assert False


    @pytest.mark.run(order=63)
    def test_063_Verify_logs_for_failed_AD_user_login(self):
        display_msg("Verify logs for AD user failed login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*AD authentication for user invalid failed.*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*AD authentication for user invalid failed.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*Login_Denied.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=64)
    def test_064_Remove_AD_from_the_Authentication_Policy_list(self):
        display_msg("Remove AD service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Add Local, RADIUS, TACACS and LDAP to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS and LDAP added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS and LDAP addition to the authentiation policy list failed")
            assert False


    @pytest.mark.run(order=65)
    def test_065_Configure_AD_server_details_with_nested_group_query_enabled(self):
        response = ib_NIOS.wapi_request("GET",object_type="ad_auth_service")
        print(response)
        ref_ad = json.loads(response)[0]['_ref']
        print("\n")
        print(ref_ad)
        display_msg("Configuring AD server details with mgmt port in the grid")
        data={
                "name": "adserver",
                "ad_domain": config.ad_domain_ssl,
                "nested_group_querying": True,
                "domain_controllers": [
                    {
                        "auth_port": 636,
                        "disabled": False,
                        "fqdn_or_ip": config.ad_fqdn,
                        "encryption": "SSL",
                        "use_mgmt_port": True
                    }
                ]
            }
        response = ib_NIOS.wapi_request('PUT', ref=ref_ad,fields=json.dumps(data))
        display_msg(response)
        if bool(re.match("\"ad_auth_service*.",str(response))):
            display_msg("AD service configured sucessfully")
            assert True
        else:
            display_msg("AD service configuration failed")
            assert False
    

    @pytest.mark.run(order=66)
    def test_066_Add_AD_to_the_Authentication_Policy_list(self):
        display_msg("Add AD service to the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS, LDAP and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False


    @pytest.mark.run(order=67)
    def test_067_Login_to_the_grid_using_AD_credentials_and_execute_cli_command(self):
        display_msg("Logging into the grid using AD credentials via CLI")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ad_nested_user1+'@'+config.grid_vip,timeout=30)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ad_pass_ssl)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            print(output)
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=68)
    def test_068_Verify_logs_for_AD_user_login(self):
        display_msg("Verify logs for AD user login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*AD authentication succeeded for user "+config.ad_nested_user1+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*AD Authentication Succeeded.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ad_nested_user1+".*Login_Allowed.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=69)
    def test_069_Login_to_the_grid_using_invalid_credentials_and_check_if_AD_authentication_fails(self):
        display_msg("Logging into the grid using invalid AD credentials and check if login fails")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no invalid@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ad_pass_ssl)
            child.expect("password:")
            output = child.before
            print(output)
            child.close()
            if 'Permission denied, please try again' in output:
                display_msg("Login to the grid using invalid LDAP credentials failed as expected")
                assert True
            else:
                display_msg("Login using invalid LDAP credentials passed")
                assert False


    @pytest.mark.run(order=70)
    def test_070_Verify_logs_for_failed_AD_user_login(self):
        display_msg("Verify logs for AD user failed login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*AD authentication for user invalid failed.*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*AD authentication for user invalid failed.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*Login_Denied.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=71)
    def test_071_Remove_AD_from_the_Authentication_Policy_list(self):
        display_msg("Remove AD service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Add Local, RADIUS, TACACS and LDAP to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS and LDAP added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS and LDAP addition to the authentiation policy list failed")
            assert False


    @pytest.mark.run(order=72)
    def test_072_Configure_AD_server_details_with_nested_group_query_enabled(self):
        response = ib_NIOS.wapi_request("GET",object_type="ad_auth_service")
        print(response)
        ref_ad = json.loads(response)[0]['_ref']
        print("\n")
        print(ref_ad)
        display_msg("Configuring AD server details with mgmt port in the grid")
        data={
                "name": "adserver",
                "ad_domain": config.ad_domain_ssl,
                "nested_group_querying": True,
                "disable_default_search_path": True,
                "additional_search_paths": [config.additional_search_path],
                "domain_controllers": [
                    {
                        "auth_port": 636,
                        "disabled": False,
                        "fqdn_or_ip": config.ad_fqdn,
                        "encryption": "SSL",
                        "use_mgmt_port": True
                    }
                ]
            }
        response = ib_NIOS.wapi_request('PUT', ref=ref_ad,fields=json.dumps(data))
        display_msg(response)
        if bool(re.match("\"ad_auth_service*.",str(response))):
            display_msg("AD service configured sucessfully")
            assert True
        else:
            display_msg("AD service configuration failed")
            assert False
    

    @pytest.mark.run(order=73)
    def test_073_Add_AD_to_the_Authentication_Policy_list(self):
        display_msg("Add AD service to the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS, LDAP and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False


    @pytest.mark.run(order=74)
    def test_074_Login_to_the_grid_using_AD_credentials_and_execute_cli_command(self):
        display_msg("Logging into the grid using AD credentials via CLI")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ad_nested_user2+'@'+config.grid_vip,timeout=30)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ad_pass_ssl)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            print(output)
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=75)
    def test_075_Verify_logs_for_AD_user_login(self):
        display_msg("Verify logs for AD user login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*AD authentication succeeded for user "+config.ad_nested_user2+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*AD Authentication Succeeded.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ad_nested_user2+".*Login_Allowed.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=76)
    def test_076_Login_to_the_grid_using_invalid_credentials_and_check_if_AD_authentication_fails(self):
        display_msg("Logging into the grid using invalid AD credentials and check if login fails")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no invalid@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ad_pass_ssl)
            child.expect("password:")
            output = child.before
            print(output)
            child.close()
            if 'Permission denied, please try again' in output:
                display_msg("Login to the grid using invalid LDAP credentials failed as expected")
                assert True
            else:
                display_msg("Login using invalid LDAP credentials passed")
                assert False


    @pytest.mark.run(order=77)
    def test_077_Verify_logs_for_failed_AD_user_login(self):
        display_msg("Verify logs for AD user failed login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*AD authentication for user invalid failed.*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*AD authentication for user invalid failed.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*Login_Denied.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=78)
    def test_078_Assign_remote_users_admin_group_as_superuser(self):
        map_remote_user_to_the_group()

    
    @pytest.mark.run(order=79)
    def test_079_Login_to_the_grid_using_LDAP_credentials_as_superuser_and_execute_cli_command(self):
        display_msg("Logging into the grid using LDAP credentials via CLI as a superuser")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ldap_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            display_msg(output)
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=80)
    def test_080_Verify_logs_for_LDAP_user_login_as_superuser(self):
        display_msg("Verify logs for LDAP user login as superuser")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info LDAP authentication succeeded for user "+config.ldap_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv("LDAP Authentication Succeeded for user '"+config.ldap_username+"'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ldap_username+".*auth=LDAP.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False



    @pytest.mark.run(order=81)
    def test_081_Assign_remote_users_admin_group_as_non_superuser(self):
        map_remote_user_to_the_group('non-superuser')

    
    @pytest.mark.run(order=82)
    def test_082_Login_to_the_grid_using_LDAP_credentials_as_non_superuser_and_execute_cli_command(self):
        display_msg("Logging into the grid using LDAP credentials via CLI as a non-superuser")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ldap_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            child.close()
            if 'Error: The user does not have sufficient privileges to run this command' in output:
                display_msg("The user was not able to execute command as a super user")
                assert True
            else:
                display_msg("The user was able to execute command as a super user")
                assert False


    @pytest.mark.run(order=83)
    def test_083_Verify_logs_for_LDAP_user_login_as_non_superuser(self):
        display_msg("Verify logs for LDAP user login as non-superuser")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info LDAP authentication succeeded for user "+config.ldap_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv("LDAP Authentication Succeeded for user '"+config.ldap_username+"'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ldap_username+".*auth=LDAP.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=84)
    def test_084_Assign_remote_users_admin_group_as_superuser(self):
        map_remote_user_to_the_group()

    @pytest.mark.run(order=85)
    def test_085_Change_the_LDAP_settings_to_use_Group_Authentication_Type_As_Posix(self):
        logging.info("Change the LDAP settings to use Group Authentication Type as POSIX")
        response = ib_NIOS.wapi_request("GET",object_type="ldap_auth_service")
        ref = json.loads(response)[0]['_ref']
        data={'ldap_group_authentication_type':'POSIX_GROUP'}
        response = ib_NIOS.wapi_request('PUT', ref=ref, fields=json.dumps(data), grid_vip=config.grid_vip)
        print(response)
        if bool(re.match("\"ldap_auth_service*.",str(response))):
            display_msg("LDAP service configuration changes sucessfull")
            assert True
        else:
            display_msg("LDAP service configuration changes failed")
            assert False


    @pytest.mark.run(order=86)
    def test_086_Login_to_the_grid_using_LDAP_credentials_and_execute_cli_command(self):
        display_msg("Logging into the grid using LDAP credentials via CLI")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ldap_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            print(output)
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=87)
    def test_087_Verify_logs_for_LDAP_user_login(self):
        display_msg("Verify logs for LDAP user login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info LDAP authentication succeeded for user "+config.ldap_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv("LDAP Authentication Succeeded for user '"+config.ldap_username+"'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ldap_username+".*auth=LDAP.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=88)
    def test_088_Login_to_the_grid_using_invalid_credentials_and_check_if_LDAP_authentication_fails(self):
        display_msg("Logging into the grid using invalid LDAP credentials and check if login fails")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no invalid@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("password:")
            output = child.before
            print(output)
            child.close()
            if 'Permission denied, please try again' in output:
                display_msg("Login to the grid using invalid LDAP credentials failed as expected")
                assert True
            else:
                display_msg("Login using invalid LDAP credentials passed")
                assert False


    @pytest.mark.run(order=89)
    def test_089_Verify_logs_for_failed_LDAP_user_login(self):
        display_msg("Verify logs for LDAP user failed login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info No authentication methods succeeded for user invalid.*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*LDAP Authentication Failed for user 'invalid'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*Login_Denied.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=90)
    def test_090_Remove_LDAP_from_the_Authentication_Policy_list(self):
        display_msg("Remove LDAP service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False

    @pytest.mark.run(order=91)
    def test_091_Change_the_LDAP_settings_to_use_LDAP_Search_Scope_as_one_level(self):
        logging.info("Change the LDAP settings to use LDAP Search scope as ONELEVEL")
        response = ib_NIOS.wapi_request("GET",object_type="ldap_auth_service")
        ref = json.loads(response)[0]['_ref']
        print(ref)
        #data={'ldap_group_authentication_type':'GROUP_ATTRIBUTE',"servers":[{"address":"10.197.38.101","base_dn":"ou=People,dc=ldapserver,dc=local"}],"search_scope": "ONELEVEL"}
        data={
                "name": "ldap",
                "servers": [
                {
                    "address": config.auth_server,
                    "version": "V3",
                    "base_dn": "ou=People,dc=ldapserver,dc=local",
                    "authentication_type": "ANONYMOUS",
                    "encryption": "NONE",
                    "port": 389,
                    }],
                "ldap_group_authentication_type": "GROUP_ATTRIBUTE",
                "search_scope": "ONELEVEL",
                "ldap_user_attribute": "uid",
                "timeout": 5,
                "retries":5,
                "recovery_interval":30
            }
        response = ib_NIOS.wapi_request('PUT', ref=ref, fields=json.dumps(data), grid_vip=config.grid_vip)
        print(response)
        if bool(re.match("\"ldap_auth_service*.",str(response))):
            display_msg("LDAP service configuration changes sucessfull")
            assert True
        else:
            display_msg("LDAP service configuration changes failed")
            assert False


    @pytest.mark.run(order=92)
    def test_092_Add_LDAP_from_the_Authentication_Policy_list(self):
        display_msg("Add LDAP service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS, LDAP and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False

    @pytest.mark.run(order=93)
    def test_093_Login_to_the_grid_using_LDAP_credentials_and_execute_cli_command(self):
        display_msg("Logging into the grid using LDAP credentials via CLI")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ldap_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            print(output)
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=94)
    def test_094_Verify_logs_for_LDAP_user_login(self):
        display_msg("Verify logs for LDAP user login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info LDAP authentication succeeded for user "+config.ldap_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv("LDAP Authentication Succeeded for user '"+config.ldap_username+"'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ldap_username+".*auth=LDAP.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=95)
    def test_095_Login_to_the_grid_using_invalid_credentials_and_check_if_LDAP_authentication_fails(self):
        display_msg("Logging into the grid using invalid LDAP credentials and check if login fails")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no invalid@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("password:")
            output = child.before
            print(output)
            child.close()
            if 'Permission denied, please try again' in output:
                display_msg("Login to the grid using invalid LDAP credentials failed as expected")
                assert True
            else:
                display_msg("Login using invalid LDAP credentials passed")
                assert False


    @pytest.mark.run(order=96)
    def test_096_Verify_logs_for_failed_LDAP_user_login(self):
        display_msg("Verify logs for LDAP user failed login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info No authentication methods succeeded for user invalid.*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*LDAP Authentication Failed for user 'invalid'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*Login_Denied.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False

    @pytest.mark.run(order=97)
    def test_097_Remove_LDAP_from_the_Authentication_Policy_list(self):
        display_msg("Remove LDAP service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False

    @pytest.mark.run(order=98)
    def test_098_Change_the_LDAP_settings_to_use_LDAP_Search_Scope_as_base(self):
        logging.info("Change the LDAP settings to use LDAP Search scope as BASE")
        response = ib_NIOS.wapi_request("GET",object_type="ldap_auth_service")
        ref = json.loads(response)[0]['_ref']
        print(ref)
        #data={'ldap_group_authentication_type':'GROUP_ATTRIBUTE',"servers":[{"address":"10.197.38.101","base_dn":"ou=People,dc=ldapserver,dc=local"}],"search_scope": "ONELEVEL"}
        data={
                "name": "ldap",
                "servers": [
                {
                    "address": config.auth_server,
                    "version": "V3",
                    "base_dn": "uid=user1_ldap,ou=People,dc=ldapserver,dc=local",
                    "authentication_type": "ANONYMOUS",
                    "encryption": "NONE",
                    "port": 389,
                    }],
                "ldap_group_authentication_type": "GROUP_ATTRIBUTE",
                "search_scope": "BASE",
                "ldap_user_attribute": "uid",
                "timeout": 5,
                "retries":5,
                "recovery_interval":30
            }
        response = ib_NIOS.wapi_request('PUT', ref=ref, fields=json.dumps(data), grid_vip=config.grid_vip)
        print(response)
        if bool(re.match("\"ldap_auth_service*.",str(response))):
            display_msg("LDAP service configuration changes sucessfull")
            assert True
        else:
            display_msg("LDAP service configuration changes failed")
            assert False


    @pytest.mark.run(order=99)
    def test_099_Add_LDAP_from_the_Authentication_Policy_list(self):
        display_msg("Add LDAP service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS, LDAP and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False

    @pytest.mark.run(order=100)
    def test_100_Login_to_the_grid_using_LDAP_credentials_and_execute_cli_command(self):
        display_msg("Logging into the grid using LDAP credentials via CLI")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ldap_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            print(output)
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=101)
    def test_101_Verify_logs_for_LDAP_user_login(self):
        display_msg("Verify logs for LDAP user login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info LDAP authentication succeeded for user "+config.ldap_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv("LDAP Authentication Succeeded for user '"+config.ldap_username+"'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ldap_username+".*auth=LDAP.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=102)
    def test_102_Login_to_the_grid_using_invalid_credentials_and_check_if_LDAP_authentication_fails(self):
        display_msg("Logging into the grid using invalid LDAP credentials and check if login fails")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no invalid@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("password:")
            output = child.before
            print(output)
            child.close()
            if 'Permission denied, please try again' in output:
                display_msg("Login to the grid using invalid LDAP credentials failed as expected")
                assert True
            else:
                display_msg("Login using invalid LDAP credentials passed")
                assert False


    @pytest.mark.run(order=103)
    def test_103_Verify_logs_for_failed_LDAP_user_login(self):
        display_msg("Verify logs for LDAP user failed login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info No authentication methods succeeded for user invalid.*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*LDAP Authentication Failed for user 'invalid'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*Login_Denied.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False

    @pytest.mark.run(order=104)
    def test_104_Remove_LDAP_from_the_Authentication_Policy_list(self):
        display_msg("Remove LDAP service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False

    @pytest.mark.run(order=105)
    def test_105_Change_the_LDAP_settings_to_use_authenticated_login(self):
        logging.info("Change the LDAP settings to use LDAP Authenticated login")
        response = ib_NIOS.wapi_request("GET",object_type="ldap_auth_service")
        ref = json.loads(response)[0]['_ref']
        print(ref)
        #data={'ldap_group_authentication_type':'GROUP_ATTRIBUTE',"servers":[{"address":"10.197.38.101","base_dn":"ou=People,dc=ldapserver,dc=local"}],"search_scope": "ONELEVEL"}
        data={
                "name": "ldap",
                "servers": [
                {
                    "address": config.auth_server,
                    "version": "V3",
                    "base_dn": "dc=ldapserver,dc=local",
                    "authentication_type": "AUTHENTICATED",
                    "bind_user_dn": "cn=admin,dc=ldapserver,dc=local",
                    "bind_password": config.ldap_password,
                    "encryption": "NONE",
                    "port": 389,
                    }],
                "ldap_group_authentication_type": "GROUP_ATTRIBUTE",
                "search_scope": "SUBTREE",
                "ldap_user_attribute": "uid",
                "timeout": 5,
                "retries":5,
                "recovery_interval":30
            }
        response = ib_NIOS.wapi_request('PUT', ref=ref, fields=json.dumps(data), grid_vip=config.grid_vip)
        print(response)
        if bool(re.match("\"ldap_auth_service*.",str(response))):
            display_msg("LDAP service configuration changes sucessfull")
            assert True
        else:
            display_msg("LDAP service configuration changes failed")
            assert False


    @pytest.mark.run(order=106)
    def test_106_Add_LDAP_from_the_Authentication_Policy_list(self):
        display_msg("Add LDAP service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS, LDAP and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False

    @pytest.mark.run(order=107)
    def test_107_Login_to_the_grid_using_LDAP_credentials_and_execute_cli_command(self):
        display_msg("Logging into the grid using LDAP credentials via CLI")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ldap_username+'@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            print(output)
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=108)
    def test_108_Verify_logs_for_LDAP_user_login(self):
        display_msg("Verify logs for LDAP user login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info LDAP authentication succeeded for user "+config.ldap_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv("LDAP Authentication Succeeded for user '"+config.ldap_username+"'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ldap_username+".*auth=LDAP.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=109)
    def test_109_Login_to_the_grid_using_invalid_credentials_and_check_if_LDAP_authentication_fails(self):
        display_msg("Logging into the grid using invalid LDAP credentials and check if login fails")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no invalid@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("password:")
            output = child.before
            print(output)
            child.close()
            if 'Permission denied, please try again' in output:
                display_msg("Login to the grid using invalid LDAP credentials failed as expected")
                assert True
            else:
                display_msg("Login using invalid LDAP credentials passed")
                assert False


    @pytest.mark.run(order=110)
    def test_110_Verify_logs_for_failed_LDAP_user_login(self):
        display_msg("Verify logs for LDAP user failed login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info No authentication methods succeeded for user invalid.*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*LDAP Authentication Failed for user 'invalid'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*Login_Denied.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False

    @pytest.mark.run(order=111)
    def test_111_Add_DNS_resolver(self):
        logging.info("Add DNS resolver")
        get_ref = ib_NIOS.wapi_request('GET', object_type="grid")
        grid_ref = json.loads(get_ref)[0]['_ref']
        data = {"dns_resolver_setting":{"resolvers":[config.resolver],"search_domains": []}}
        resolver_ref = ib_NIOS.wapi_request('PUT', ref=grid_ref, fields=json.dumps(data))
        logging.info(resolver_ref)
        if bool(re.match("\"grid*.",str(resolver_ref))):
            logging.info("Resolver added successfully")
        else:
            raise Exception("DNS resolver update failed")

    @pytest.mark.run(order=112)
    def test_112_Upload_LDAP_CA_cert(self):
        dir_name="certificate/"
        base_filename="ldap_ca_cert.pem"
        token = common_util.generate_token_from_file(dir_name,base_filename)
        print(token)
        data = {"token": token, "certificate_usage":"EAP_CA"}
        response = ib_NIOS.wapi_request('POST', object_type="fileop",fields=json.dumps(data),params="?_function=uploadcertificate")
        print(response)
        #Verify if certificate was uploaded
        get_ref = ib_NIOS.wapi_request('GET', object_type="cacertificate")
        ref_certs = json.loads(get_ref)
        count = 0
        for i in ref_certs:
            if i["distinguished_name"] == "CN=\"LDAP CA\",OU=\"QA\",O=\"Infoblox\",L=\"Bengaluru\",ST=\"Karnataka\",C=\"IN\"":
                count +=1
        if count!= 0:
            print("LDAP CA certificate uploaded successfully")
            assert True
        else:
            print("LDAP CA certificate upload failed")
            assert False





    @pytest.mark.run(order=113)
    def test_113_Remove_LDAP_from_the_Authentication_Policy_list(self):
        display_msg("Remove LDAP service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS, LDAP and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False

    @pytest.mark.run(order=114)
    def test_114_Change_the_LDAP_settings_to_use_SSL_login(self):
        logging.info("Change the LDAP settings to use LDAP SSL login")
        response = ib_NIOS.wapi_request("GET",object_type="ldap_auth_service")
        ref = json.loads(response)[0]['_ref']
        print(ref)
        #data={'ldap_group_authentication_type':'GROUP_ATTRIBUTE',"servers":[{"address":"10.197.38.101","base_dn":"ou=People,dc=ldapserver,dc=local"}],"search_scope": "ONELEVEL"}
        data={
                "name": "ldap",
                "servers": [
                {
                    "address": config.auth_server_fqdn,
                    "version": "V3",
                    "base_dn": "dc=ldapserver,dc=local",
                    "authentication_type": "AUTHENTICATED",
                    "bind_user_dn": "cn=admin,dc=ldapserver,dc=local",
                    "bind_password": config.ldap_password,
                    "encryption": "SSL",
                    "port": 636,
                    }],
                "ldap_group_authentication_type": "GROUP_ATTRIBUTE",
                "search_scope": "SUBTREE",
                "ldap_user_attribute": "uid",
                "timeout": 5,
                "retries":5,
                "recovery_interval":30
            }
        response = ib_NIOS.wapi_request('PUT', ref=ref, fields=json.dumps(data), grid_vip=config.grid_vip)
        print(response)
        if bool(re.match("\"ldap_auth_service*.",str(response))):
            display_msg("LDAP service configuration changes sucessfull")
            assert True
        else:
            display_msg("LDAP service configuration changes failed")
            assert False


    @pytest.mark.run(order=115)
    def test_115_Add_LDAP_from_the_Authentication_Policy_list(self):
        display_msg("Add LDAP service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS, LDAP and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False

    @pytest.mark.run(order=116)
    def test_116_Login_to_the_grid_using_LDAP_credentials_and_execute_cli_command(self):
        display_msg("Logging into the grid using LDAP credentials via CLI")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ldap_username+'@'+config.grid_vip,timeout=30)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            print(output)
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=117)
    def test_117_Verify_logs_for_LDAP_user_login(self):
        display_msg("Verify logs for LDAP user login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info LDAP authentication succeeded for user "+config.ldap_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv("LDAP Authentication Succeeded for user '"+config.ldap_username+"'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ldap_username+".*auth=LDAP.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=118)
    def test_118_Login_to_the_grid_using_invalid_credentials_and_check_if_LDAP_authentication_fails(self):
        display_msg("Logging into the grid using invalid LDAP credentials and check if login fails")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no invalid@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("password:")
            output = child.before
            print(output)
            child.close()
            if 'Permission denied, please try again' in output:
                display_msg("Login to the grid using invalid LDAP credentials failed as expected")
                assert True
            else:
                display_msg("Login using invalid LDAP credentials passed")
                assert False


    @pytest.mark.run(order=119)
    def test_119_Verify_logs_for_failed_LDAP_user_login(self):
        display_msg("Verify logs for LDAP user failed login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info No authentication methods succeeded for user invalid.*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*LDAP Authentication Failed for user 'invalid'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*Login_Denied.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False

    @pytest.mark.run(order=120)
    def test_120_Remove_LDAP_from_the_Authentication_Policy_list(self):
        display_msg("Remove LDAP service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False

    @pytest.mark.run(order=121)
    def test_121_Change_the_LDAP_settings_to_connect_through_mgmt_interface(self):
        logging.info("Change the LDAP settings to connect through mgmt interface")
        response = ib_NIOS.wapi_request("GET",object_type="ldap_auth_service")
        ref = json.loads(response)[0]['_ref']
        print(ref)
        #data={'ldap_group_authentication_type':'GROUP_ATTRIBUTE',"servers":[{"address":"10.197.38.101","base_dn":"ou=People,dc=ldapserver,dc=local"}],"search_scope": "ONELEVEL"}
        data={
                "name": "ldap",
                "servers": [
                {
                    "address": config.auth_server_fqdn,
                    "version": "V3",
                    "base_dn": "dc=ldapserver,dc=local",
                    "authentication_type": "AUTHENTICATED",
                    "bind_user_dn": "cn=admin,dc=ldapserver,dc=local",
                    "bind_password": config.ldap_password,
                    "encryption": "SSL",
                    "port": 636,
                    "use_mgmt_port": True
                    }],
                "ldap_group_authentication_type": "GROUP_ATTRIBUTE",
                "search_scope": "SUBTREE",
                "ldap_user_attribute": "uid",
                "timeout": 5,
                "retries":5,
                "recovery_interval":30
            }
        response = ib_NIOS.wapi_request('PUT', ref=ref, fields=json.dumps(data), grid_vip=config.grid_vip)
        print(response)
        if bool(re.match("\"ldap_auth_service*.",str(response))):
            display_msg("LDAP service configuration changes sucessfull")
            assert True
        else:
            display_msg("LDAP service configuration changes failed")
            assert False


    @pytest.mark.run(order=122)
    def test_122_Add_LDAP_from_the_Authentication_Policy_list(self):
        display_msg("Add LDAP service from the authentication policy")
        
        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)
        
        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)
        
        display_msg("Fetch RADIUS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(response)[0]['_ref']
        display_msg("RADIUS server ref : "+radius_ref)


        display_msg("Fetch TACACS server ref")
        response = ib_NIOS.wapi_request('GET', object_type="tacacsplus:authservice")
        tacacs_ref = json.loads(response)[0]['_ref']
        display_msg("TACACS server ref : "+tacacs_ref)
        

        display_msg("Fetch LDAP server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ldap_auth_service")
        ldap_ref = json.loads(response)[0]['_ref']
        display_msg("LDAP server ref : "+ldap_ref)


        display_msg("Fetch AD server ref")
        response = ib_NIOS.wapi_request('GET', object_type="ad_auth_service")
        ad_ref = json.loads(response)[0]['_ref']
        display_msg("AD server ref : "+ad_ref)


        display_msg("Add Local, RADIUS, TACACS, LDAP and AD server to the authentiation policy list")
        data={"auth_services":[local_user_ref,radius_ref,tacacs_ref,ad_ref,ldap_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Local, RADIUS, TACACS, LDAP and AD server added to the authentiation policy list successfully")
            sleep(30)
            assert True
        else:
            display_msg("Local, RADIUS, TACACS, LDAP and AD server addition to the authentiation policy list failed")
            assert False

    @pytest.mark.run(order=123)
    def test_123_Login_to_the_grid_using_LDAP_credentials_and_execute_cli_command(self):
        display_msg("Logging into the grid using LDAP credentials via CLI")
        display_msg("Starting log capture")
        sleep(30)
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no '+config.ldap_username+'@'+config.grid_vip,timeout=30)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("Infoblox >")
            child.sendline("show status")
            child.expect("Infoblox >")
            output = child.before
            print(output)
            child.close()
            if 'Hostname:       '+config.grid1_master_fqdn in output:
                display_msg("The user was  able to execute command as a super user")
                assert True
            else:
                display_msg("The user was not able to execute command as a super user")
                assert False


    @pytest.mark.run(order=124)
    def test_124_Verify_logs_for_LDAP_user_login(self):
        display_msg("Verify logs for LDAP user login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info LDAP authentication succeeded for user "+config.ldap_username+".*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv("LDAP Authentication Succeeded for user '"+config.ldap_username+"'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*"+config.ldap_username+".*auth=LDAP.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False


    @pytest.mark.run(order=125)
    def test_125_Login_to_the_grid_using_invalid_credentials_and_check_if_LDAP_authentication_fails(self):
        display_msg("Logging into the grid using invalid LDAP credentials and check if login fails")
        display_msg("Starting log capture")
        log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        display_msg("Logging into the grid")
        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no invalid@'+config.grid_vip,timeout=300)
        except pexpect.TIMEOUT:
            display_msg("Unable to connect to the grid, please check connectivity to the grid")
            assert False
        else:
            child.expect("password:")
            child.sendline(config.ldap_password)
            child.expect("password:")
            output = child.before
            print(output)
            child.close()
            if 'Permission denied, please try again' in output:
                display_msg("Login to the grid using invalid LDAP credentials failed as expected")
                assert True
            else:
                display_msg("Login using invalid LDAP credentials passed")
                assert False


    @pytest.mark.run(order=126)
    def test_126_Verify_logs_for_failed_LDAP_user_login(self):
        display_msg("Verify logs for LDAP user failed login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying syslog for the authentication logs")
        validate = logv(".*info No authentication methods succeeded for user invalid.*","/var/log/syslog",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Syslog verification successfull")
        else:
             display_msg("Syslog verification unsuccessfull")

        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv(".*LDAP Authentication Failed for user 'invalid'.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*Login_Denied.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==3:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False

    @pytest.mark.run(order=127)
    def test_127_Perform_WAPI_call_using_LDAP_user(self):
        display_msg("Starting log capture")
        #log("start","/var/log/syslog",config.grid_vip)
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        logging.info("Perform WAPI call using LDAP user")
        get_ref = ib_NIOS.wapi_request('GET', object_type="grid",user=config.ldap_username,password=config.ldap_password)
        grid_ref = json.loads(get_ref)[0]['_ref']
        print(grid_ref)
        if bool(re.match("\"grid*.",str(grid_ref))):
            display_msg("WAPI call successfull")
        else:
            display_msg("WAPI call failed")
    

    @pytest.mark.run(order=128)
    def test_128_Verify_logs_for_LDAP_user_login(self):
        display_msg("Verify logs for LDAP user login")
        sleep(20)
        display_msg("Stopping log capture")

        #log("stop","/var/log/syslog",config.grid_vip)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying infoblox.log for the authentication logs")
        validate = logv("Login_Allowed.*auth=LDAP.*apparently_via=API","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*auth=LDAP.*apparently_via=API","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==2:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False
  


    @pytest.mark.run(order=129)
    def test_129_Perform_WAPI_call_using_invalid_LDAP_user(self):
        display_msg("Starting log capture")
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/infoblox/var/audit.log",config.grid_vip)
        sleep(10)
        logging.info("Perform WAPI call using invalid LDAP user")
        try:
            get_ref = ib_NIOS.wapi_request('GET', object_type="grid",user='invalid',password=config.ldap_password)
        except Exception as e:
            print("WAPI call failed with invalid LDAP user")
            assert True
        else:
            print("WAPI call passed with invalid LDAP user")
            assert False
        

    @pytest.mark.run(order=130)
    def test_130_Verify_logs_for_LDAP_user_login(self):
        display_msg("Verify logs for invalid LDAP user login")
        sleep(20)
        display_msg("Stopping log capture")

        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        count=0
        display_msg("Verifying infoblox.log for the authentication logs")
        #To be uncommented for 9.0 branch
        #validate = logv(".*Unable to log in with the LDAP server.*"+config.auth_server+".*with username 'invalid'.*","/infoblox/var/infoblox.log",config.grid_vip)

        #This validation is for 8.6 branch
        validate = logv(".*Login_Denied.*apparently_via=API.*","/infoblox/var/infoblox.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("infoblox.log verification successfull")
        else:
             display_msg("infoblox.log verification unsuccessfull")


        display_msg("Verifying audit.log for the authentication logs")
        validate = logv(".*Login_Denied.*apparently_via=API.*","/infoblox/var/audit.log",config.grid_vip)
        if validate != None:
            count +=1
            display_msg("Audit.log verification successfull")
        else:
             display_msg("Audit.log verification unsuccessfull")

        if count ==2:
            display_msg("All log verifications successful")
            assert True
        else:
            display_msg("Log verification failed, check above logs for the failures")
            assert False

    @pytest.mark.run(order=131)
    def test_131_Remove_all_services_auth_policy(self):

        display_msg("Remove all service from the authentication policy")

        display_msg("Fetch Authentication policy ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy')
        auth_policy_ref = json.loads(response)[0]['_ref']
        display_msg("Authentication Policy ref: "+auth_policy_ref)

        display_msg("Fetch local user ref")
        response = ib_NIOS.wapi_request('GET',object_type='authpolicy?_return_fields=auth_services')
        local_user_ref = json.loads(response)[0]['auth_services'][0]
        display_msg("Local user ref: "+local_user_ref)

        display_msg("Add Local authentiation policy list")
        data={"auth_services":[local_user_ref]}
        response = ib_NIOS.wapi_request('PUT',fields=json.dumps(data),ref=auth_policy_ref)
        display_msg(response)
        if bool(re.match("\"authpolicy*.",str(response))):
            display_msg("Keep only Local user added to the authentiation policy list successfully")
            sleep(10)
            assert True
        else:
            display_msg("Keep only Local user to the authentiation policy list failed")
            assert False


    @pytest.mark.run(order=132)
    def test_132_remove_radius_configured(self):

        res1 = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        print(res1)
        res1 = json.loads(res1)
        radiusref=res1[0][u'_ref']
        response = ib_NIOS.wapi_request('DELETE',ref=radiusref)
        print(response)

    @pytest.mark.run(order=133)
    def test_133_radius_auth_server(self):
        display_msg("----------------------------------------------------")
        display_msg("|     Testcase 1 Execution Started                 |")
        display_msg("----------------------------------------------------")

        display_msg("Creating radius service in authentication server group")
        data={
                "name": "radius",
                "servers": [
            {
                "address": config.rad1_ip,
                "shared_secret": "testing123",
                "auth_port": 1812,
                "auth_type": "PAP",
                "disable": False,
                "use_accounting": False,
                "use_mgmt_port": False
            },
                    {
                        "address": config.rad2_ip,
                        "auth_port": 1812,
                        "auth_type": "PAP",
                        "shared_secret": "testing123",
                        "use_accounting": False,
                        "use_mgmt_port": False
                    }
                    ],
                "enable_cache": True,
                "mode": "ROUND_ROBIN"
                }
        radiusref = ib_NIOS.wapi_request('POST', object_type="radius:authservice",fields=json.dumps(data))
        print(radiusref)
        display_msg(radiusref)
        radiusref = json.loads(radiusref)
        if type(radiusref) == tuple:
            if response[0]==400 or response[0]==401:
                assert False
            else:
                assert True
        print("Test Case 133 Execution Completed")


    @pytest.mark.run(order=134)
    def test_134_add_ipv4_NAC_filters(self):

        data={
                "name": "good guys",
                "expression": "((Sophos.ComplianceState=\"Compliant\" OR Sophos.ComplianceState=\"PartialCompliant\") AND Sophos.UserClass!=\"NACDeny\" AND Radius.ServerState=\"success\" AND Radius.ServerError=\"false\" AND Radius.ServerResponse=\"accept\")"
        #"expression": "(Sophos.ComplianceState=\"Compliant\" OR Sophos.ComplianceState=\"PartialCompliant\" OR Radius.ServerError=\"false\" OR Radius.ServerState=\"success\")"        
            }
        Nacref1 = ib_NIOS.wapi_request('POST', object_type="filternac",fields=json.dumps(data))
        print(Nacref1)
        if type(Nacref1) == tuple:
            if Nacref1[0]==400 or Nacref1[0]==401:
                assert False
            else:
                assert True
                print("Test Case 134 Execution Completed")


    @pytest.mark.run(order=135)
    def test_135_add_ipv4_MAC_filters(self):

        data={"name": "mac_filter"}
        Nacref1 = ib_NIOS.wapi_request('POST', object_type="filtermac",fields=json.dumps(data))
        print(Nacref1)
        # MAC Filter Address
        mac_filter_address_1 = {"filter":"mac_filter","mac":"B1:11:20:00:00:D0"}
        response = ib_NIOS.wapi_request('POST', object_type="macfilteraddress", fields=json.dumps(mac_filter_address_1))
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                assert False
            else:
                assert True
        print("Test Case 135 Execution Completed")

    @pytest.mark.run(order=136)
    def test_136_enable_dhcp_create_network_range(self):

                #Create a DHCP network 10.0.0.0/8
        data = {"network": "10.0.0.0/8","network_view": "default","members":[{"_struct": "dhcpmember","ipv4addr":config.grid_lan_vip}]}
        response = ib_NIOS.wapi_request('POST', object_type="network", fields=json.dumps(data))
        print(response)
        if type(response)  == tuple:
            if response[0] == 400 or response[0] == 401:
                assert False

        print("Created the ipv4network 10.0.0.0/8 in default view")

                #Create a range from 10.0.0.1 to 10.0.0.10
        data = {"network":"10.0.0.0/8","start_addr":"10.0.0.1","end_addr":"10.0.0.10","network_view": "default","name": "Production","member": {"_struct": "dhcpmember","ipv4addr": config.grid_lan_vip}}
        response = ib_NIOS.wapi_request('POST', object_type="range", fields=json.dumps(data))
        print (response)
        if type(response)  == tuple:
            if response[0] == 400 or response[0] == 401:
                assert False

                #Enable DHCP service

        get_ref = ib_NIOS.wapi_request('GET', object_type="member:dhcpproperties")
        ref1 = json.loads(get_ref)[0]['_ref']
        data = {"enable_dhcp":True}
        response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data))
        print(response)

        grid =  ib_NIOS.wapi_request('GET', object_type="grid",)
        ref = json.loads(grid)[0]['_ref']

        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        response = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),)
        sleep(20) #wait for 20 secs for the service to get started

        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                assert False
            else:
                assert True
        print("Test Case 136 Execution Completed")


    @pytest.mark.run(order=137)
    def test_137_add_radius_server_in_dhcp_auth_server_group(self):

        radius_ref = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radius_ref = json.loads(radius_ref)
        radiusref=radius_ref[0]['_ref']

        get_ref = ib_NIOS.wapi_request('GET', object_type="member:dhcpproperties")
        ref1 = json.loads(get_ref)[0]['_ref']

        data = {"authn_server_group_enabled": True,"auth_server_group":"radius"}
        response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data))
        print(response)
        if type(response)  == tuple:
            if response[0] == 400 or response[0] == 401:
                assert False

        grid =  ib_NIOS.wapi_request('GET', object_type="grid",)
        ref = json.loads(grid)[0]['_ref']

        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        response = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),)
        sleep(20) #wait for 20 secs for the service to get started

        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                assert False
            else:
                assert True
        print("Test Case 137 Execution Completed")

    @pytest.mark.run(order=138)
    def test_138_add_nac_mac_filters_to_range(self):

        get_ref = ib_NIOS.wapi_request('GET', object_type="range")
        ref1 = json.loads(get_ref)[0]['_ref']

        data={"logic_filter_rules": [{"filter": "good guys", "type": "NAC"},{"filter": "mac_filter", "type": "MAC"}], "nac_filter_rules": [{"filter": "good guys","permission": "Allow"}],"mac_filter_rules": [{"filter": "mac_filter","permission": "Allow"}]}
        response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data))
        print(response)
        if type(response)  == tuple:
            if response[0] == 400 or response[0] == 401:
                assert False

        grid =  ib_NIOS.wapi_request('GET', object_type="grid")
        ref = json.loads(grid)[0]['_ref']

        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        response = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),)
        sleep(20) #wait for 20 secs for the service to get started
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                assert False
            else:
                assert True

        print("Test Case 138 Execution Completed")

    @pytest.mark.run(order=139)
    def test_139_send_dras_request(self):
        display_msg("----------------------------------------------------")
        display_msg("|     Testcase 139 Execution Started                 |")
        display_msg("----------------------------------------------------")
        log("start","/var/log/messages",config.grid_vip)
        dras_requests()
        log("stop","/var/log/messages",config.grid_vip)
        LookFor = "DHCPACK"
        logs=logv(LookFor,"/var/log/messages",config.grid_vip)

        if logs==None:
            logging.info("Test Case 139 Execution Completed")
            assert False
        else:
            logging.info("Test Case 139 Execution failed")
            assert True

    @pytest.mark.run(order=140)
    def test_140_modify_nac_filters_to_range(self):

        get_ref = ib_NIOS.wapi_request('GET', object_type="range")
        ref1 = json.loads(get_ref)[0]['_ref']
        #only nac filter rules should be present and no mac filter
        data={"nac_filter_rules": [{"filter": "good guys","permission": "Allow"}]}
        response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data))
        print(response)
        if type(response)  == tuple:
            if response[0] == 400 or response[0] == 401:
                assert False

        grid =  ib_NIOS.wapi_request('GET', object_type="grid")
        ref = json.loads(grid)[0]['_ref']

        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        response = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),)
        sleep(20) #wait for 20 secs for the service to get started
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                assert False
            else:
                assert True

        print("Test Case 140 Execution Completed")

    @pytest.mark.run(order=141)
    def test_141_send_dras_request(self):
        display_msg("----------------------------------------------------")
        display_msg("|     Testcase 141 Execution Started                 |")
        display_msg("----------------------------------------------------")
        log("start","/var/log/messages",config.grid_vip)
        dras_requests()
        log("stop","/var/log/messages",config.grid_vip)
        LookFor = "DHCPACK"    
        logs=logv(LookFor,"/var/log/messages",config.grid_vip)

        if logs==None:
            logging.info("Test Case 141 Execution Completed")
            assert False
        else:
            logging.info("Test Case 141 Execution failed")
            assert True

    @pytest.mark.run(order=142)
    def test_142_deny_nac_filters_to_range(self):

        get_ref = ib_NIOS.wapi_request('GET', object_type="range")
        ref1 = json.loads(get_ref)[0]['_ref']

        data={"nac_filter_rules": [{"filter": "good guys","permission": "Deny"}],"mac_filter_rules": [{"filter": "mac_filter","permission": "Allow"}]}
        response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data))
        print(response)
        if type(response)  == tuple:
            if response[0] == 400 or response[0] == 401:
                assert False

        grid =  ib_NIOS.wapi_request('GET', object_type="grid")
        ref = json.loads(grid)[0]['_ref']

        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        response = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),)
        sleep(20) #wait for 20 secs for the service to get started
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                assert False
            else:
                assert True

        print("Test Case 142 Execution Completed")


    @pytest.mark.run(order=143)
    def test_143_send_dras_request(self):
        log("start","/var/log/messages",config.grid_vip)
        dras_requests()
        log("stop","/var/log/messages",config.grid_vip)
        LookFor = "DHCPACK"
        logs=logv(LookFor,"/var/log/messages",config.grid_vip)

        if logs==None:
            logging.info("Test Case 143 Execution Completed")
            assert False
        else:
            logging.info("Test Case 143 Execution failed")
            assert True

    @pytest.mark.run(order=144)
    def test_144_deny_nac_filters_to_range(self):

        get_ref = ib_NIOS.wapi_request('GET', object_type="range")
        ref1 = json.loads(get_ref)[0]['_ref']

        data={"nac_filter_rules": [{"filter": "good guys","permission": "Allow"}],"mac_filter_rules": [{"filter": "mac_filter","permission": "Deny"}]}
        response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data))
        print(response)
        if type(response)  == tuple:
            if response[0] == 400 or response[0] == 401:
                assert False

        grid =  ib_NIOS.wapi_request('GET', object_type="grid")
        ref = json.loads(grid)[0]['_ref']

        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        response = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),)
        sleep(20) #wait for 20 secs for the service to get started
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                assert False
            else:
                assert True

        print("Test Case 144 Execution Completed")
    

    @pytest.mark.run(order=145)
    def test_145_send_dras_request(self):
        log("start","/var/log/messages",config.grid_vip)
        dras_requests()
        log("stop","/var/log/messages",config.grid_vip)
        LookFor = "DHCPACK"
        logs=logv(LookFor,"/var/log/messages",config.grid_vip)

        if logs==None:
            logging.info("Test Case 145 Execution Completed")
            assert True
        else:
            logging.info("Test Case 145 Execution failed")
            assert False

    @pytest.mark.run(order=146)
    def test_146_deny_nac_filters_to_range(self):

        get_ref = ib_NIOS.wapi_request('GET', object_type="range")
        ref1 = json.loads(get_ref)[0]['_ref']

        data={"nac_filter_rules": [{"filter": "good guys","permission": "Deny"}],"mac_filter_rules": [{"filter": "mac_filter","permission": "Deny"}]}
        response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data))
        print(response)
        if type(response)  == tuple:
            if response[0] == 400 or response[0] == 401:
                assert False

        grid =  ib_NIOS.wapi_request('GET', object_type="grid")
        ref = json.loads(grid)[0]['_ref']

        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        response = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),)
        sleep(20) #wait for 20 secs for the service to get started
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                assert False
            else:
                assert True

        print("Test Case 146 Execution Completed")


    @pytest.mark.run(order=147)
    def test_147_send_dras_request(self):
        log("start","/var/log/messages",config.grid_vip)
        dras_requests()
        log("stop","/var/log/messages",config.grid_vip)
        LookFor = "DHCPACK"
        logs=logv(LookFor,"/var/log/messages",config.grid_vip)

        if logs==None:
            logging.info("Test Case 147 Execution Completed")
            assert True
        else:
            logging.info("Test Case 147 Execution failed")
            assert False

    @pytest.mark.run(order=148)
    def test_148_deny_nac_filters_to_range(self):

        get_ref = ib_NIOS.wapi_request('GET', object_type="range")
        ref1 = json.loads(get_ref)[0]['_ref']

        data={"nac_filter_rules": [{"filter": "good guys","permission": "Deny"}]}
        response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data))
        print(response)
        if type(response)  == tuple:
            if response[0] == 400 or response[0] == 401:
                assert False

        grid =  ib_NIOS.wapi_request('GET', object_type="grid")
        ref = json.loads(grid)[0]['_ref']

        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        response = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),)
        sleep(20) #wait for 20 secs for the service to get started
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                assert False
            else:
                assert True

        print("Test Case 148 Execution Completed")


    @pytest.mark.run(order=149)
    def test_149_send_dras_request(self):
        log("start","/var/log/messages",config.grid_vip)
        dras_requests()
        log("stop","/var/log/messages",config.grid_vip)
        LookFor = "no permitted ranges with available leases"
        logs=logv(LookFor,"/var/log/messages",config.grid_vip)

        if logs==None:
            logging.info("Test Case 149 Execution Completed")
            assert False
        else:
            logging.info("Test Case 149 Execution failed")
            assert True

    @pytest.mark.run(order=150) 
    def test_150_clean_data(self):

        display_msg("----------------------------------------------------")
        display_msg("|     Testcase 150 Execution Started                 |")
        display_msg("----------------------------------------------------")

        get_ref = ib_NIOS.wapi_request('GET', object_type="member:dhcpproperties")
        ref1 = json.loads(get_ref)[0]['_ref']
        data = {"authn_server_group_enabled": False}
        response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data))
        display_msg(response)

        get_ref = ib_NIOS.wapi_request('GET', object_type="network")
        ref1 = json.loads(get_ref)[0]['_ref']
        response = ib_NIOS.wapi_request('DELETE',ref=ref1)
        display_msg(response)

        radius_ref = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        radiusref = json.loads(radius_ref)[0]['_ref']
        display_msg(radiusref)
        response = ib_NIOS.wapi_request('DELETE',ref=radiusref)
        display_msg(response)

        #filternac
        get_ref = ib_NIOS.wapi_request('GET', object_type="filternac")
        ref1 = json.loads(get_ref)[0]['_ref']
        response = ib_NIOS.wapi_request('DELETE',ref=ref1)
        display_msg(response)

        #filtermac
        get_ref = ib_NIOS.wapi_request('GET', object_type="filtermac")
        ref1 = json.loads(get_ref)[0]['_ref']
        response = ib_NIOS.wapi_request('DELETE',ref=ref1)
        display_msg(response)

        grid =  ib_NIOS.wapi_request('GET', object_type="grid")
        ref = json.loads(grid)[0]['_ref']
        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        response = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data))



