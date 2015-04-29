#!/usr/bin/python

import re
import xmlrpclib
import sys
import subprocess

api = xmlrpclib.ServerProxy('https://rpc.gandi.net/xmlrpc/')


def main():
    apikey = ''
    domain = ''
    record = ''

    from optparse import OptionParser
    optp = OptionParser()
    optp.add_option('-a', '--api',    help='Specify API key')
    optp.add_option('-d', '--domain', help='Specify domain')
    optp.add_option('-r', '--record', help='Specify record data')
    (opts, args) = optp.parse_args()

    #Set Variables
    domain = opts.domain
    apikey = opts.api
    record = opts.record
    ttl = 300
    
    if apikey == None:
        print ("The apikey needs to be specified")
        usage()
        sys.exit()

    if domain == None:
        print ("The domain name needs to be specified")
        usage()
        sys.exit()

    if record == None:                                           
        print ("The Record name to update needs to be specified")
        usage()                                        
        sys.exit()                                     
                    
    if check_if_apikey_exists(apikey) == False:
        print ("Apikey " + apikey + " does not exist or is malformed")
        usage()
        sys.exit()

    if check_if_domain_exists(apikey, domain) == False:
        print ("Domain " + domain + " does not exist")
        usage()
        sys.exit()

    router_address = get_router_address()
    if router_address == False:
        print ("Router address is incorrect: " + str(router_address))
        sys.exit()
    

    # Fetch the active zone id
    zone_id = get_zoneid_by_domain(apikey, domain)
    zone_id = 1505828
    if get_zone_address(apikey, zone_id, record) == False:
        print ("Record: " + record + " was not found in zone: " + str(zone_id))
        usage()
        sys.exit()

    # Test to see if zone file needs to be updated
    zone_address = get_zone_address(apikey, zone_id, record)
    
    if router_address != zone_address:
        print ("ZoneID: " + str(zone_id))
        print ("Zone  : " + zone_address) 
        print ("Router: " + router_address)                                                             
        print ("Will proceed to update zone file " + str(zone_id) + " with the following ip : " + router_address)
        
    else:
        print ("ZoneID: " + str(zone_id))
        print ("Zone  : " + zone_address)        
        print ("Router: " + router_address)
        print ("IP's match so nothing left todo, EXITING.")
        sys.exit()
    
    # Create new version 
    new_version_id = api.domain.zone.version.new(apikey, zone_id, 0)
    print ("New Version :" + str(new_version_id))

    # Find record id needing to be updated 
    record_id = get_record_id(apikey, zone_id, record, new_version_id)
    print ("Record ID to update: " + str(record_id))

    # Update record     
    updated_record = api.domain.zone.record.update(apikey, zone_id, new_version_id, { 'id' : record_id }, { "type" : "A", "name": record, "value": router_address, "ttl": ttl })
    print ("Record updated as such:")
    print updated_record

    # Set new updated version to the active zone version. 
    api.domain.zone.version.set(apikey, zone_id, new_version_id)

    check_updated_successfully(apikey, zone_id, record, router_address)






def usage():
    print("Usage: gandi-dyndns --api=APIKEY --domain=DOMAIN --record=RECORD --ttl=TTL")

def api_version(apikey):
    return api.version.info(apikey)

def check_if_domain_exists(apikey, domain):
    try:
        api.domain.info(apikey, domain)
        return True
    except xmlrpclib.Fault as err:
        return False

def check_if_apikey_exists(apikey):
    try:
        api_version(apikey)
        return True
    except xmlrpclib.Fault as err:
        return False

def check_if_record_exists(apikey, zone_id, record, rtype): 
    recordListOptions = {"name": record, 
                         "type": rtype}

def domain_info(apikey, domain):
    return api.domain.info(apikey, domain)

def get_zoneid_by_domain(apikey, domain):
    return domain_info(apikey, domain)['zone_id']

def get_router_address():
    ip_address = subprocess.check_output("ifconfig pppoe-wan | grep 'inet addr:' | awk '{print $2}' | sed 's/addr://g' | tr -d '\n'",shell=True)
    return ip_address

def get_zoneid_by_domain(apikey, domain):
    return domain_info(apikey, domain)['zone_id']

def get_zone_record(apikey, zone_id):
    return api.domain.zone.record.list(apikey, zone_id, 0)

def get_new_zone_record(apikey, zone_id, new_version_id):
    return api.domain.zone.record.list(apikey, zone_id, new_version_id)

def get_zone_address(apikey, zone_id, record):
    address = False
    for i in range (0, len(get_zone_record(apikey, zone_id))):
         tmp = get_zone_record(apikey, zone_id)[i]
         if tmp['name'] == record:
              address = tmp['value']
    return address 

def get_record_id(apikey, zone_id, record, new_version_id):             
    row_id = False
    for i in range (0, len(get_new_zone_record(apikey, zone_id, new_version_id))):
         tmp = get_new_zone_record(apikey, zone_id, new_version_id)[i]
         if tmp['name'] == record:                        
              row_id = tmp['id']                             
    return row_id           

def check_updated_successfully(apikey, zone_id, record, router_address):
    zone_address = get_zone_address(apikey, zone_id, record)
    if router_address != zone_address:                                                                                                                         
        print ("Router: " + router_address)                                                                                                                    
        print ("Zone  : " + zone_address)                                                                                                                         
        print ("Something went wrong... Try again? ")                                              
        sys.exit()
                                                                                                                                                               
    else:                                                                                                                                                      
        print ("Router: " + router_address)                                                                                                                    
        print ("Zone  : " + zone_address + " from zone_id: " + str(zone_id))                                                                                   
        print ("IP's match as expected now... Wait till dns records propegate.")                                                                                                    
        sys.exit()                          

main ()
