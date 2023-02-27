import os
import re
import config
import pytest
import unittest
import logging
import json
import sys
from time import sleep
import ib_utils.ib_NIOS as ib_NIOS
import shlex
from time import sleep
import subprocess
import pexpect
import paramiko
from ib_utils.start_stop_logs import log_action as log
from ib_utils.file_content_validation import log_validation as logv

def display_msg(x=""):
    """
    Additional function.
    """
    logging.info(x)
    print(x)

def dras_requests():
    """
    Perform dras command
    """
    print("sending dras")
    dras_cmd = 'sudo /import/tools/qa/tools/dras/dras -i ' +str(config.grid_lan_vip)+ ' -q 5 -R 5 -t 10000 -n 1 -h -a B1:11:20:00:00:D0 -r'
    print(dras_cmd)
    dras_cmd1 = os.system(dras_cmd)
    print (dras_cmd1)

class RFE_10028(unittest.TestCase):

    @pytest.mark.run(order=0)
    def test_000_Remove_RADIUS_from_the_Authentiation_Policy_list(self):
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

    @pytest.mark.run(order=1)
    def test_001_remove_radius_configured(self):
        res1 = ib_NIOS.wapi_request('GET', object_type="radius:authservice")
        print(res1)
        res1 = json.loads(res1)
        radiusref=res1[0][u'_ref']
        response = ib_NIOS.wapi_request('DELETE',ref=radiusref)
        print(response)

    @pytest.mark.run(order=2)
    def test_002_radius_auth_server(self):
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
        print("Test Case 2 Execution Completed")


    @pytest.mark.run(order=3)
    def test_003_add_ipv4_NAC_filters(self):

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
		print("Test Case 3 Execution Completed")


    @pytest.mark.run(order=4)
    def test_004_add_ipv4_MAC_filters(self):

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
        print("Test Case 4 Execution Completed")

    @pytest.mark.run(order=5)
    def test_005_enable_dhcp_create_network_range(self):

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
        print("Test Case 5 Execution Completed")


    @pytest.mark.run(order=6)
    def test_006_add_radius_server_in_dhcp_auth_server_group(self):

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
        print("Test Case 6 Execution Completed")

    @pytest.mark.run(order=7)
    def test_007_add_nac_mac_filters_to_range(self):

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

        print("Test Case 7 Execution Completed")

    '''
    @pytest.mark.run(order=7)
    def test_007_Capture_Tcpdump_for_accounting_radius(self):
        display_msg("----------------------------------------------------")	
        display_msg("Capture Tcpdump logs for DHCP lease request with radius enabled")
        display_msg("----------------------------------------------------")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('#')
        child.sendline('nohup tcpdump -v -i any -n port 1812 or port 67 or port 68 -c 30 > rad1.txt &')
        child.expect('')
        child.sendline('\n')
        child.expect('#')
        child.close()
    '''

    @pytest.mark.run(order=8)
    def test_008_send_dras_request(self):
        display_msg("----------------------------------------------------")
        display_msg("|     Testcase 008 Execution Started                 |")
        display_msg("----------------------------------------------------")
        log("start","/var/log/messages",config.grid_vip)
        dras_requests()
	log("stop","/var/log/messages",config.grid_vip)
	LookFor = "DHCPACK"	
        logs=logv(LookFor,"/var/log/messages",config.grid_vip)
	
	if logs==None:
            logging.info("Test Case 8 Execution Completed")
            assert False
        else:
            logging.info("Test Case 8 Execution failed")
            assert True

    '''
    @pytest.mark.run(order=9)
    def test_009_validate_radius_accounting_tcpdump(self):

        display_msg("----------------------------------------------------")
        display_msg("|     Testcase 009 Execution Started                 |")
        display_msg("----------------------------------------------------")

        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('#')
        child.sendline('ls -lrt')
        child.expect('#')
        child.sendline('cat rad1.txt')
        child.expect('#')
        output = child.before
        print("#####OUTPUT#####",output)
        if re.search(r".*"+config.grid_vip+".*"+config.rad1_ip+".radius: RADIUS, Access-Request.*\n.*RADIUS, Access-Reject.*\n.*\n.*"+config.grid_vip+".*"+config.rad2_ip+".radius: RADIUS, Access-Request.*\n.*"+config.rad2_ip+".radius > "+config.grid_vip+".*RADIUS, Access-Accept.*",output):
            assert True
            child.close()
        else:
            assert False
            child.close()

    @pytest.mark.run(order=10)
    def test_010_Kill_process(self):

        display_msg("----------------------------------------------------")
        display_msg("|     Testcase 010 Execution Started                 |")
        display_msg("----------------------------------------------------")

        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('#')
        child.sendline("killall tcpdump")
        child.expect("#")
        output = child.before
        print("$$$$$$$$$$$$$",output)
    '''

    @pytest.mark.run(order=11)
    def test_011_modify_nac_filters_to_range(self):

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

        print("Test Case 11 Execution Completed")

    '''
    @pytest.mark.run(order=12)
    def test_012_Capture_Tcpdump_for_accounting_radius(self):
        display_msg("----------------------------------------------------")
        display_msg("Capture Tcpdump logs for DHCP lease request with radius enabled")
        display_msg("----------------------------------------------------")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('#')
        child.sendline('nohup tcpdump -v -i any -n port 1812 or port 67 or port 68 -c 30 > rad1.txt &')
        child.expect('')
        child.sendline('\n')
        child.expect('#')
        child.close()
    '''

    @pytest.mark.run(order=13)
    def test_013_send_dras_request(self):
        display_msg("----------------------------------------------------")
        display_msg("|     Testcase 013 Execution Started                 |")
        display_msg("----------------------------------------------------")
        log("start","/var/log/messages",config.grid_vip)
        dras_requests()
        log("stop","/var/log/messages",config.grid_vip)
        LookFor = "DHCPACK"    
        logs=logv(LookFor,"/var/log/messages",config.grid_vip)

        if logs==None:
            logging.info("Test Case 13 Execution Completed")
            assert False
        else:
            logging.info("Test Case 13 Execution failed")
            assert True

    '''
    @pytest.mark.run(order=14)
    def test_014_validate_radius_accounting_tcpdump(self):

        display_msg("----------------------------------------------------")
        display_msg("|     Testcase 014 Execution Started                 |")
        display_msg("----------------------------------------------------")

        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('#')
        child.sendline('ls -lrt')
        child.expect('#')
        child.sendline('cat rad1.txt')
        child.expect('#')
        output = child.before
        print("#####OUTPUT#####",output)
        if re.search(r".*"+config.grid_vip+".*"+config.rad1_ip+".radius: RADIUS, Access-Request.*\n.*RADIUS, Access-Reject.*\n.*\n.*"+config.grid_vip+".*"+config.rad2_ip+".radius: RADIUS, Access-Request.*\n.*"+config.rad2_ip+".radius > "+config.grid_vip+".*RADIUS, Access-Accept.*",output):
            assert True
            child.close()
        else:
            assert False
            child.close()


    @pytest.mark.run(order=15)
    def test_015_Kill_process(self):

        display_msg("----------------------------------------------------")
        display_msg("|     Testcase 015 Execution Started                 |")
        display_msg("----------------------------------------------------")

        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('#')
        child.sendline("killall tcpdump")
        child.expect("#")
        output = child.before
        print("$$$$$$$$$$$$$",output)
    '''

    @pytest.mark.run(order=16)
    def test_016_deny_nac_filters_to_range(self):

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

        print("Test Case 16 Execution Completed")


    @pytest.mark.run(order=17)
    def test_017_send_dras_request(self):
        log("start","/var/log/messages",config.grid_vip)
        dras_requests()
        log("stop","/var/log/messages",config.grid_vip)
        LookFor = "DHCPACK"
        logs=logv(LookFor,"/var/log/messages",config.grid_vip)

        if logs==None:
            logging.info("Test Case 17 Execution Completed")
            assert False
        else:
            logging.info("Test Case 17 Execution failed")
            assert True

    @pytest.mark.run(order=18)
    def test_018_deny_nac_filters_to_range(self):

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

        print("Test Case 18 Execution Completed")
    

    @pytest.mark.run(order=19)
    def test_019_send_dras_request(self):
        log("start","/var/log/messages",config.grid_vip)
        dras_requests()
        log("stop","/var/log/messages",config.grid_vip)
        LookFor = "DHCPACK"
        logs=logv(LookFor,"/var/log/messages",config.grid_vip)

        if logs==None:
            logging.info("Test Case 19 Execution Completed")
            assert True
        else:
            logging.info("Test Case 19 Execution failed")
            assert False

    @pytest.mark.run(order=20)
    def test_020_deny_nac_filters_to_range(self):

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

        print("Test Case 20 Execution Completed")


    @pytest.mark.run(order=21)
    def test_021_send_dras_request(self):
        log("start","/var/log/messages",config.grid_vip)
        dras_requests()
        log("stop","/var/log/messages",config.grid_vip)
        LookFor = "DHCPACK"
        logs=logv(LookFor,"/var/log/messages",config.grid_vip)

        if logs==None:
            logging.info("Test Case 21 Execution Completed")
            assert True
        else:
            logging.info("Test Case 21 Execution failed")
            assert False

    @pytest.mark.run(order=22)
    def test_022_deny_nac_filters_to_range(self):

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

        print("Test Case 22 Execution Completed")


    @pytest.mark.run(order=23)
    def test_023_send_dras_request(self):
        log("start","/var/log/messages",config.grid_vip)
        dras_requests()
        log("stop","/var/log/messages",config.grid_vip)
        LookFor = "no permitted ranges with available leases"
        logs=logv(LookFor,"/var/log/messages",config.grid_vip)

        if logs==None:
            logging.info("Test Case 23 Execution Completed")
            assert False
        else:
            logging.info("Test Case 12 Execution failed")
            assert True

    @pytest.mark.run(order=24) 
    def test_024_clean_data(self):

        display_msg("----------------------------------------------------")
        display_msg("|     Testcase 013 Execution Started                 |")
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
