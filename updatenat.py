import json
import logging
import sys

import boto3
import botocore
from dnslib import pan_client as dnsclient

import pan.xapi
from config import config as CFG
from netaddr import IPNetwork, IPAddress

s3 = boto3.resource('s3')

addr_xpath = "/config/devices/entry/vsys/entry/address"
commit_cmd = "<commit><partial><device-and-network>excluded</device-and-network></partial></commit>"

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# Compares supplied IP to defined AZs
def __find_az_for_ip(ip):
    az_ip_pair = dict()
    for az in CFG.AZ_PREFIX_MAP:
        az_subnet = CFG.AZ_PREFIX_MAP[az]
        if IPAddress(ip) in IPNetwork(az_subnet):
            az_ip_pair = {az: ip}
    if not az_ip_pair:
        raise ValueError("IP does not match any defined AZ subnet")
    return az_ip_pair


# Generates an Address Object Name based on ELB FQDN
def __generate_addr_obj_name(elb_name):
    elb_policy_name = elb_name.split('.')[0]
    return elb_policy_name


# Updates supplied Address Object in candidate configuration
def set_addr_object(api_session, policy_name, nat_dst_ip):
    object_xpath = addr_xpath + "/entry[@name='%s']/ip-netmask" % policy_name
    element = "<ip-netmask>%s</ip-netmask>" % nat_dst_ip
    logger.info("Updating object %s on %s with IP Address %s via XML API" % (policy_name,
                                                                             api_session.hostname,
                                                                             nat_dst_ip))
    api_session.edit(object_xpath, element)
    return api_session.status


# Gets the requested Address Object from running configuration
def get_addr_object(api_session, addr_object):
    addr = dict()
    object_xpath = addr_xpath + "/entry[@name='%s']" % addr_object
    logger.info("Looking up %s on %s via XML API" % (addr_object, api_session.hostname))
    api_session.show(object_xpath)
    this_element = api_session.element_result
    addr['name'] = this_element[0].attrib['name']
    addr['address'] = this_element[0][0].text
    return addr


# This function iterates through the AZs in the supplied ELB dict,
# and updates the respective firewall if needed
def update_firewalls(elb, firewalls):
    # Process each ELB
    for elb_name, elb_ips in elb.iteritems():
        addr_obj_name = __generate_addr_obj_name(elb_name)

        for az in elb_ips:
            # Create an XML API session with firewall
            fwl_session = pan.xapi.PanXapi(api_username=firewalls[az]['api_username'],
                                           api_password=firewalls[az]['api_password'],
                                           hostname=firewalls[az]['hostname'])
            # Get the Address Object
            elb_object = get_addr_object(fwl_session, addr_obj_name)
            # Compare the Address Object against the resolved ELB IP
            if elb_object['address'] in elb_ips[az]:
                logger.info("Object %s with address %s matches ELB IP %s" % (elb_object['name'],
                                                                             elb_object['address'],
                                                                             elb_ips[az]))
            else:
                logger.info("Object %s with address %s does not match ELB IP %s" % (elb_object['name'],
                                                                                    elb_object['address'],
                                                                                    elb_ips[az]))
                # Update the address object with the resolved ELB IP address
                status = set_addr_object(fwl_session, addr_obj_name, elb_ips[az])
                logger.info("%s - Updating Address Object %s with IP address %s" % (status, addr_obj_name, elb_ips[az]))
                fwl_session.commit(cmd=commit_cmd, sync=False)
                logger.info("%s - committed configuration to firewall %s" % (fwl_session.status, fwl_session.hostname))


# Create a new database with the ELBs defined in configuration
def init_db(elbs):
    db_contents = {}
    for elb in elbs:
        resolved_elb = resolve_elb_ips(elb)
        db_contents.update(resolved_elb)
    save_db(db_contents)
    return db_contents


# Load the database from the configured S3 bucket/key
def load_db():
    filedata = s3.Object(CFG.S3_BUCKET, CFG.DB_FILE).get()
    db_data = json.load(filedata['Body'])
    return db_data


# Save the database file to the configured S3 bucket/key
def save_db(db_data):
    jsondata = json.dumps(db_data)
    s3.Object(CFG.S3_BUCKET, CFG.DB_FILE).put(Body=jsondata)


# Resolve the ELB's IP addresses and match them with an AZ
def resolve_elb_ips(elb):
    # Get the IP addresses of this ELB in an array
    ip_addresses = dnsclient.pan_dig(elb)
    if ip_addresses == "":
        raise ValueError("Could not resolve %s" % elb)
    ip_addresses = sorted(ip_addresses.split('\n'))
    # New dict, key name is the ELB name
    elb_listing = {elb: {}}
    # Iterate through the IPs and match them to an AZ
    for ip in ip_addresses:
        ip_az = __find_az_for_ip(ip)
        # Update the dict with the AZ and IP
        elb_listing[elb].update(ip_az)
    return elb_listing


# TODO: Get rid of this
# Find value in a dict
def check_needs_update(elb, iplist):
    if elb in iplist:
        return False
    return True


# Called by the Lambda
def lambda_handler(event, context):
    logger.info("Lambda triggered with event details: %r" % event)
    logger.info("Beginning run of updatenat script, lambda time remaining: %s" % context.get_remaining_time_in_millis())
    process_elbs(context)
    logger.info("Completed run of updatenat script, lambda time remaining: %s" % context.get_remaining_time_in_millis())


# Process all ELBs and update firewalls, meaty part
def process_elbs(context):
    # Instance variable to see if we need to attempt update of Address Objects
    update = False

    # Read the DB, handle it if it's not there
    try:
        this_iplist = load_db()
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            this_iplist = init_db(CFG.ELB_LIST)
            update = True
        else:
            raise

    # Variable to see if DB needs to be updated
    db_change = False

    # TODO: Process each firewall rather than each ELB to speed up processing
    # Process ELBs
    for ELB in CFG.ELB_LIST:
        # Resolve ELB IP Addresses
        elb_ips = resolve_elb_ips(ELB)
        logger.info("Beginning processing of ELB %s" % ELB)

        # Compare ELB with DB
        if ELB in this_iplist:
            # Force an update if we're in debug mode
            update = update if not CFG.DEBUG else True

            # If we haven't yet been told to update, check if we need to
            if not update:
                update = True if cmp(elb_ips[ELB], this_iplist[ELB]) != 0 else False

            if update:
                # IP is different, update the firewalls
                logger.info("ELB IPs %r do not match DB IPs %r, performing update check." % ELB)
                # Update each firewall if required
                update_firewalls(elb_ips, CFG.FIREWALLS)
                # Update the IP list with the new IP address
                this_iplist[ELB] = elb_ips[ELB]
                # Mark the DB to be written
                db_change = True
            else:
                logger.info("ELB IPs %r match DB IPs %r, no action required." % (elb_ips[ELB], this_iplist[ELB]))
        else:
            # ELB wasn't in DB, so add to DB
            logger.info("ELB %s not in DB, adding with IPs %r" % (ELB, elb_ips[ELB]))
            this_iplist.update(elb_ips)
            db_change = True

        # Finished processing this ELB
        logger.info("Finished processing of ELB %s" % ELB)
        if context is not None:
            logger.info("lambda time remaining: %s" % context.get_remaining_time_in_millis())

    # Save the DB if needed
    if db_change:
        save_db(this_iplist)


if __name__ == '__main__':
    # Set up console logging
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Begin processing
    logger.info("Script triggered via command line, beginning processing")
    session = boto3.Session(aws_access_key_id=CFG.AWS_ACCESS_KEY,
                            aws_secret_access_key=CFG.AWS_SECRET_KEY,
                            region_name=CFG.AWS_REGION)

    s3 = session.resource('s3')

    process_elbs(None)

    logger.info("Script triggered via command line, finished processing")
    sys.exit(0)
