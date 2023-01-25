"""
 Copyright (c) Infoblox Inc., 2016
 ReportName          : Threat Protection Event Count By Member
 ReportCategory      : Threat Protection.
 Number of Test cases: 1
 Execution time      : 
 Execution Group     : Minute Group (HG)
 Description         : Event Count Dashboard.

 Author   : shashikala R S
 History  : 03/02/2021 (Created)
 Reviewer : 
"""
import pytest
import unittest
import logging
import subprocess
import json
import ConfigParser
import os
import ib_utils.ib_validaiton as ib_validation
import ib_utils.ib_system as ib_system
import ib_utils.ib_NIOS as ib_NIOS
import ib_utils.ib_get as ib_get
import config
import pexpect
import sys
import random
import ib_utils.ib_NIOS as ib_NIOS
import ib_utils.ib_get as ib_get
from logger import logger
from time import sleep
from ib_utils.ib_system import search_dump as search_dump
from ib_utils.ib_validaiton import compare_results as compare_results
"""
TEST Steps:
      1.  Input/Preparation  : Prparation will be called by separte script as reports will be updated every minute
                               
      2.  Search     : Performing Search operaion with default/custom filter
      3.  Validation : comparing Search results with Reterived  'Threat Protection Event Count by Member' report without delta.
"""

class Threat_Protection_Event_Count_by_Member(unittest.TestCase):
    @classmethod
    def setup_class(cls):
        logger.info('-'*15+"START:Threat Protection Event Count by Member"+'-'*15)
       
        cls.test1=[]
        temp={}
        temp["Member"]=config.grid_member1_fqdn
        temp["Critical Event Count"]="0"
        #temp["Major Event Count"]="17"
        temp["Warning Event Count"]="0"
        # temp["Informational Event Count"]="2"
        # temp["Total Event Count"]="23"
        cls.test1.append(temp)
  

        logger.info ("Input Json for validation")
        logger.info(json.dumps(cls.test1, sort_keys=True, indent=4, separators=(',', ': ')))

    def test_1_TP_Event_Count_by_Member(self):
        logger.info("TestCase:"+sys._getframe().f_code.co_name)
        search_str="search source=ib:ddos:events index=ib_security (host=\"*\") * * | noop | noop | bucket span=5m _time | eval SUM_COUNT=ACOUNT+DCOUNT | stats sum(eval(if(SEVERITY==\"CRITICAL\",SUM_COUNT,0))) as sumcrit, sum(eval(if(SEVERITY==\"MAJOR\",SUM_COUNT,0))) as summaj, sum(eval(if(SEVERITY==\"WARNING\",SUM_COUNT,0))) as sumwarn, sum(eval(if(SEVERITY==\"INFORMATIONAL\",SUM_COUNT,0))) as suminf by host | eval sumtot=sumcrit+summaj+sumwarn+suminf | sort -sumtot | rename host as Member | head 5 | rename sumcrit as \"Critical Event Count\", summaj as \"Major Event Count\", sumwarn as \"Warning Event Count\", suminf as \"Informational Event Count\", sumtot as \"Total Event Count\" | table \"Member\", \"Critical Event Count\", \"Major Event Count\", \"Warning Event Count\", \"Informational Event Count\", \"Total Event Count\""
        cmd = config.search_py + " '" + search_str + "' --output_mode=json"
        logger.info (cmd) 
        os.system(cmd)
        try:
            retrived_data=open(config.json_file).read()
        except Exception, e:
            logger.error('search operation failed due to %s',e)
            raise Exception("Search operation failed, Please check Grid Configuration")
        output_data = json.loads(retrived_data)
        results_list = output_data['results']
        search_dump(sys._getframe().f_code.co_name+"_search_output.txt",self.test1,results_list)
        logger.info("dumping search results in '%s' 'dumps' directory",sys._getframe().f_code.co_name+"_search_output.txt")
        logger.info("compare_results")
        result = compare_results(self.test1,results_list)
        print('-----------------------------------------------')
        print(self.test1)
        print(len(self.test1))
        print('---------------Adding Debugging line--------------------------------')
        print(results_list)
        print(len(results_list))
        print('-----------------------------------------------')
        if result == 0:
            logger.info("Search validation result: %s (PASS)",result)
        else:
            logger.error("Search validation result: %s (FAIL)",result)
        msg = 'Validation is not matching for object which is retrieved from DB %s', result
        assert result == 0, msg



    @classmethod
    def teardown_class(cls):
        logger.info('-'*15+"END:Threat Protection Event Count by Member"+'-'*15) 

