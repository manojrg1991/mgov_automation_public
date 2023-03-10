
import py
import json
import os
import re
import sys
import getopt
import ib_utils.ib_NIOS_6478 as ib_NIOS
from time import sleep
import ib_data.ib_preparation as prep
import ib_utils.ib_papi as papi
import subprocess
import ib_utils.ib_conf_gen as conf_gen
from logger import logger


os.environ["PYTHONPATH"]=os.getcwd()
"""
   -t : single_indexer, single_site_cluster, multi_site_cluster, SSC_SystemActivity, MSC_SystemActivity
   -i : Indexers separated by ':', Ex: -i '10.34.221.55' for 'Single Indexer' Similarly -i '10.34.221.55:10.34.221.56' & -i '10.34.221.55:10.34.221.56:10.34.221.57:10.34.221.58' for clusters
   -m : Members separated by ':'  (GridMaster:Member1:Member2:Member3 etc., )
   -d : DCVM_IP 
   -v : splunk_verison:wapi_version
   -p : pool_dir:pool_tag
   -n : network id say (10.34.220.0)
   -s : clinet_vm:client_ip:client_user:client_user_pw (CLIENT)
   -o : cisco_ise_ip:cisco_ise_user:cisco_ise_password:cisco_ise_secret
   -r : olympic ruleset
   -z : GRID2_IP
"""
args=sys.argv[1:]
optlist, args = getopt.getopt(args,'c:i:m:d:p:v:t:n:s:o:r:z:')
for opt, arg in optlist:
    if opt == '-t':
       run_type=arg
    if opt == '-i':
        indexer=arg
    if opt == '-m':
        members=arg
    if opt == '-v':
       splunk_version,wapi_version=arg.split(':')
    if opt == '-s':
       client_vm,client_ip,client_user,client_passwd=arg.split(':')
    if opt == '-z':
       grid2_vip=arg


"""
Configuring Master, Member & Reporting Member Variables. 
"""
logger.info("START: '%s' Reporting execuiton is started",run_type)
var_hash={}
L=members.split(':')
master=L[0]
var_hash["GRID_MASTER_VIP"] =master
var_hash["GRID_MASTER_FQDN"]="ib-"+'-'.join(master.split('.'))+".infoblox.com"
print master 
for i,member in enumerate(L[1:]):
    var_hash["GRID_MEMBER"+str(i+1)+"_VIP"]=member
    var_hash["GRID_MEMBER"+str(i+1)+"_FQDN"]="ib-"+'-'.join(member.split('.'))+".infoblox.com"
L=indexer.split(':')
for i,member in enumerate(L):
    var_hash["REPORTING_MEMBER"+str(i+1)+"_VIP"]=member
    var_hash["REPORTING_MEMBER"+str(i+1)+"_FQDN"]="ib-"+'-'.join(member.split('.'))+".infoblox.com"

if 'dcvm_ip' in locals():
     var_hash["DCVM_IP"]=dcvm_ip

var_hash["WAPI_VERSION"]=wapi_version
var_hash["SPLUNK_VERSION"]=splunk_version
#var_hash["POOL_DIR"]=pool_dir
#var_hash["POOL_TAG"]=pool_tag
var_hash["GRID2_MASTER_VIP"]=grid2_vip
var_hash["GRID2_MASTER_FQDN"]="ib-"+'-'.join(grid2_vip.split('.'))+".infoblox.com"
#olympic_ruleset
#var_hash["OLYMPIC_RULESET"]=olympic_ruleset

#CLIENT Configuraiton for reporting backup
if 'client_vm' not in locals():
    client_ip=re.findall('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',os.popen("/usr/sbin/ifconfig | grep 'inet '|grep -v '127.0.0.1'").readline())[0].rstrip()
    client_vm=os.popen("hostname").readline().rstrip()
    client_vm,client_ip,client_user,client_passwd=(client_vm,client_ip,"root","infoblox")
var_hash["CLIENT_HWID"]=client_vm
var_hash["CLIENT_IP"]=client_ip
var_hash["CLIENT_USER"]=client_user
var_hash["CLIENT_PASSWD"]=client_passwd

#CISCO Configuraiton
if 'cisco_ise_ip' not in locals():
    cisco_ise_ip,cisco_ise_user,cisco_ise_password,cisco_ise_secret=("10.36.141.15","qa","Infoblox1492","secret") #default
var_hash["CISCO_ISE_IP"]=cisco_ise_ip
var_hash["CISCO_ISE_USER"]=cisco_ise_user
var_hash["CISCO_ISE_PASSWORD"]=cisco_ise_password
var_hash["CISCO_ISE_SECRET"]=cisco_ise_secret

#SPLUNK PORT
if(run_type == 'single_indexer'):
    var_hash["INDEXER_IP"]=var_hash["REPORTING_MEMBER1_VIP"]
    var_hash["SPLUNK_PORT"]="8089"
else:
    var_hash["INDEXER_IP"]=var_hash["GRID_MASTER_VIP"]
    var_hash["SPLUNK_PORT"]="7089"


#Generating config.py Conf file
logger.info("Generating config.py configuraiotn file")
rc=conf_gen.config(**var_hash)

#Addkyes
logger.info("Adding SSH Keys on Grid Members")
papi.addkeys(master)

#Download Perl Module
logger.info("Downloading Perl Module")
papi.download_pm(master)

#Time Zone Change & Enabling SNMP configuraiton
logger.info("Changing time Zone as UTC")
papi.set_time_zone(master)


#Enabling Reporting 
logger.info("Enabling Reporting by selecting All reporting category")
papi.enable_reporting(master)

logger.info("Wait for 7 min, enabling reporting first Time.")
sleep(420)

#Generating splunkrc Conf file
logger.info("Generating .splunkrc file")
rc=conf_gen.splunkrc(var_hash["INDEXER_IP"],var_hash["SPLUNK_PORT"],var_hash["SPLUNK_VERSION"])  

if(run_type == 'single_indexer' or  'single_site_cluster' or 'multi_site_cluster'):
    logger.info("Preparation for '%s' execution (Hourly & Minute Reporting Group)",run_type)  

    #Configuring Reporting Mode. 
    if(run_type == 'single_site_cluster'):
        logger.info("Configuring 'Single Site Cluster Mode'")
        papi.configure_single_site(master)
    elif(run_type == 'multi_site_cluster'):
        logger.info("Configuring Reporting-Site extensible attribute")
        papi.configure_reporting_site(master,var_hash["REPORTING_MEMBER1_VIP"],'site1') 
        papi.configure_reporting_site(master,var_hash["REPORTING_MEMBER2_VIP"],'site1') 
        papi.configure_reporting_site(master,var_hash["REPORTING_MEMBER3_VIP"],'site2') 
        papi.configure_reporting_site(master,var_hash["REPORTING_MEMBER4_VIP"],'site2') 
        logger.info("Configuring Reporting-Site extensible attribute")
        logger.info("Configuring 'Multi Site Cluster Mode'")
        papi.configure_multi_site(master,'site1','site2')
    
    

   # logger.info("Preparation for Securtiy RPZ Reports")
    prep.rpz_security()
    pre = "python k.py"
    exe1 = os.system(pre)
    sleep(4500)

    
    logger.info("Waiting for 60 mins for intial reports to get update")

    cmd = "py.test Cloud/test_MG_vm_address_history.py Security/test_HG_dns_top_rpz_hits.py Security/test_HG_dns_top_rpz_hits_clients.py  Security/test_HG_dns_rpz_hits_mitigation_action.py --tb=long --html=regression_report.html --junit-xml=regression_results.xml -vvs"
    rm = os.system(cmd)


    logger.info("Scipt to Perform Backup/Restore Operation")
    os.system("python Backup_Restore/Backup_Restore.py")


    cmd1= "py.test Cloud/test_BRG_vm_address_history.py Security/test_HG_dns_top_rpz_hits.py Security/test_HG_dns_top_rpz_hits_clients.py  Security/test_HG_dns_rpz_hits_mitigation_action.py --tb=long --html=regression_restore_report.html --junit-xml=regression_restore_results.xml -vvs"
    rm1= os.system(cmd1)

  
'''
elif (run_type == 'SSC_SystemActivity'):
    args_str = "-k test_SSC --collect-only"
    py.test.cmdline.main(args_str.split(" "))

elif (run_type == 'MSC_SystemActivity'):
    args_str = "-k test_MSC --collect-only"
    py.test.cmdline.main(args_str.split(" "))
'''
#Report Generation.
