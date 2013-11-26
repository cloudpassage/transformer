#!/usr/bin/env python

import sys
import boto
from aws_ec2 import SecurityGroup
import cpapi
import cputils
import json

verbose = False

def findServiceByPortRange(serviceList,rule):
    rule_port = makePortRange(rule)
    rule_proto = rule.ip_protocol.lower()
    for svc in serviceList:
        if (rule_proto == svc['protocol'].lower()):
            if ((rule_port == "-1") or (rule_port == "-1--1")) and (not ('port' in svc)):
                return svc
            if (rule_port == svc['port']):
                return svc
    return None


def makePortRange(rule):
    if (rule.from_port == rule.to_port):
        rule_port = "%s" % rule.from_port
    else:
        rule_port = "%s-%s" % (rule.from_port, rule.to_port)
    if (rule_port.startswith("0-")):
        revised = "1" + rule_port[1:]
        return revised
    else:
        return rule_port


def findZoneByIpAddress(zoneList,grant):
    if (grant.cidr_ip != None):
        for zone in zoneList:
            if (grant.cidr_ip == zone['ip_address']):
                return zone
    return None


def makeService(policyName,rule):
    svc_ports = makePortRange(rule)
    if (svc_ports == "-1") or (svc_ports == "-1--1"):
        svc_ports = None
        svc_name = policyName + "_" + rule.ip_protocol.lower()
    else:
        svc_name = policyName + "_" + rule.ip_protocol.lower() + "_" + svc_ports
    svc = cputils.createFirewallServiceObj(svc_name,svc_ports,rule.ip_protocol.upper())
    return svc


def makeZone(policyName,grant):
    zone_ip_suffix = grant.cidr_ip.replace(".","-").replace("/","_")
    zone_name = policyName + "_" + zone_ip_suffix
    zone = { 'name': zone_name, 'ip_address': grant.cidr_ip }
    return zone


def findOrCreateService(haloConn,policyName,sg_rule,firewallServiceList):
    svc = findServiceByPortRange(firewallServiceList,sg_rule)
    if (svc == None):
        svc = makeService(policyName,sg_rule)
        (response, authError) = cputils.createFirewallService(haloConn,svc)
        if (response != None) and ('firewall_service' in response):
            fwsData = response['firewall_service']
            if ('id' in fwsData):
                svc['id'] = fwsData['id']
        else:
            print "Failed to create service: " + str(svc)
            return None
    return svc


def findOrCreateZone(haloConn,policyName,grant,firewallZoneList):
    zone = findZoneByIpAddress(firewallZoneList,grant)
    if (zone == None):
        zone = makeZone(policyName,grant)
        (response, authError) = cputils.createFirewallZone(haloConn,zone)
        if (response != None) and ('firewall_zone' in response):
            fwzData = response['firewall_zone']
            if ('id' in fwzData):
                zone['id'] = fwzData['id']
        else:
            print "Failed to create zone: " + str(zone)
            return None
    return zone
    

def convertRule(haloConn,policyName,sg_rule,grant,inbound,outbound,firewallServiceList,firewallZoneList):
    if sg_rule.inbound:
        chain = "INPUT"
        inbound['count'] += 1
    else:
        chain = "OUTPUT"
        outbound['count'] += 1
    ruleObj = { 'chain': chain, 'action': "ACCEPT", 'active': True }

    noService = False
    if (sg_rule.ip_protocol != "-1"): # -1 represents "all protocols", thus a wild card
        svc = findOrCreateService(haloConn,policyName,sg_rule,firewallServiceList)
        if (svc == None):
            return None
        if ('id' in svc):
            ruleObj['firewall_service'] = svc['id']
    else:
        noService = True

    noZone = False
    if (grant.cidr_ip != None) and (grant.cidr_ip != "0.0.0.0/0"):
        zone = findOrCreateZone(haloConn,policyName,grant,firewallZoneList)
        if (zone == None):
            return None
        if ('id' in zone):
            ruleObj['firewall_source'] =  { 'id': zone['id'], 'type': "FirewallZone" }
    else:
        noZone = True

    if (noZone and noService):
        # since we have an "Accept all" rule, no need to add "Deny all" rule later
        if sg_rule.inbound:
            inbound['acceptAll'] = True
        else:
            outbound['acceptAll'] = True

    return ruleObj


def makeChainObj():
    return { 'count': 0, 'acceptAll': False }


def convertSecurityGroupToHalo(haloConn,ec2SecGroup,policyName,platform):
    policyObj = { 'name': policyName, 'platform': platform }
    if (ec2SecGroup.description != None):
        policyObj['description'] = ec2SecGroup.description
    else:
        policyObj['description'] = "Conversion from EC2 Security Group %s" % ec2SecGroup.name
    ruleList = []
    if (len(ec2SecGroup.rules) > 0):
        (firewallServiceResponse, authError) = cputils.getFirewallServiceList(haloConn)
        firewallServiceList = firewallServiceResponse['firewall_services']
        (firewallZoneResponse, authError) = cputils.getFirewallZoneList(haloConn)
        firewallZoneList = firewallZoneResponse['firewall_zones']
        if (verbose):
            for svc in firewallServiceList:
                print "Service: name=%s ports=%s/%s" % (svc['name'], svc['port'], svc['protocol'])
            for zone in firewallZoneList:
                print "Zone: name=%s ip=%s" % ( zone['name'], zone['ip_address'])
        inbound = makeChainObj()
        outbound = makeChainObj()
        for sg_rule in ec2SecGroup.rules:
            for grant in sg_rule.grants:
                ruleObj = convertRule(haloConn,policyName,sg_rule,grant,inbound,outbound,
                                      firewallServiceList,firewallZoneList)
                if (ruleObj != None):
                    ruleList.append(ruleObj)
        # a "drop everything not listed above" rule
        if (inbound['count'] > 0) and (not inbound['acceptAll']):
            ruleList.append({ 'chain': "INPUT", 'action': "DROP", 'active': True })
        if (outbound['count'] > 0) and (not outbound['acceptAll']):
            ruleList.append({ 'chain': "OUTPUT", 'action': "DROP", 'active': True })

    policyObj['firewall_rules'] = ruleList
    if (platform == "windows"):
        policyObj["log_allowed"] = True;
        policyObj["log_dropped"] = True;
        policyObj["block_inbound"] = True;
        policyObj["block_outbound"] = True;
    if (verbose):
        print json.dumps(policyObj, indent=4)
    (response, authError) = haloConn.createFirewallPolicy({ 'firewall_policy': policyObj })
    if (response != None) and ('firewall_policy' in response):
        policy = response['firewall_policy']
        print "Successfully created firewall policy: id=%s" % policy['id']
    else:
        print "Failed to create firewall policy"
    return response != None


def addAwsGrant(sg,ruleProto,ruleMinPort,ruleMaxPort,ruleSource,ruleAction,ruleDirection):
    ok = False
    if (ruleDirection == "input"):
        if (ruleAction == "accept"):
            try:
                ok = sg.authorize(ruleProto,int(ruleMinPort),int(ruleMaxPort),ruleSource)
            except:
                ok = False
        elif (ruleAction == "reject") or (ruleAction == "drop"):
            try:
                ok = sg.revoke(ruleProto,int(ruleMinPort),int(ruleMaxPort),ruleSource)
            except:
                ok = False
        else:
            print >> sys.stderr, "Error: Unknown rule action: %s" % ruleAction
            return False

        info = (ruleAction, ruleProto, ruleMinPort, ruleMaxPort, ruleSource)
        if ok:
            print "    OK! Successfully added rule for %s packets: proto=%s ports=%s/%s src=%s" % info
        else:
            print "    ERROR! Failed to add rule for %s packets: proto=%s ports=%s/%s src=%s" % info
    else:
        print "    WARN! Cannot currently handle outbound rules"
    return ok


def convertFirewallPolicyToSecurityGroup(haloConn,ec2Conn,policy,groupName):
    id = policy['id']
    (policyWrapper, authError) = haloConn.getFirewallPolicyDetails(id)
    if ('firewall_policy' in policyWrapper):
        policy = policyWrapper['firewall_policy']
    if (verbose):
        print json.dumps(policy,indent=4)
    # return
    # AWS _requires_ an SG description. If we don't have one, reuse name.
    groupDescription = groupName
    if ('description' in policy) and (len(policy['description']) > 0):
        groupDescription = policy['description']
    print "Creating security group named: %s" % groupName
    print "  Description: %s" % groupDescription
    sg = ec2Conn.create_security_group(groupName,groupDescription)
    for rule in policy['firewall_rules']:
        ruleProto = None
        ruleMinPort = None
        ruleMaxPort = None
        ruleSources = ["0.0.0.0/0"]
        ruleAction = rule['action'].lower()
        ruleDirection = rule['chain'].lower()
        print "    Creating rule: chain=%s action=%s" % (rule['chain'], rule['action'])
        if ('firewall_service' in rule):
            service = rule['firewall_service']
            print "      Protocol=%s Port(s)=%s" % (service['protocol'], service['port'])
            ruleProto = service['protocol'].lower()
            if ('-' in service['port']):
                print "Need to split: %s" % service['port']
                fields = service['port'].split("-")
                if (fields != None) and (len(fields) == 2):
                    ruleMinPort = fields[0]
                    ruleMaxPort = fields[1]
            else:
                ruleMinPort = service['port']
                ruleMaxPort = service['port']
        if ('firewall_source' in rule):
            source = rule['firewall_source']
            sourceType = "?"
            sourceName = "?"
            if ('type' in source):
                sourceType = source['type']
            if ('name' in source):
                sourceName = source['name']
            elif ('username' in source):
                sourceName = source['username']
            if (sourceType == "FirewallZone") and ('ip_address' in source):
                ruleSources = source['ip_address'].split(", ")
            print "      Source: type=%s name=%s" % (sourceType, sourceName)
        if (ruleProto != None) and (ruleMinPort != None) and (ruleMaxPort != None):
            for ruleSource in ruleSources:
                if not ("/" in ruleSource):
                    ruleSource = ruleSource + "/32" # all IP addresses need to be in CIDR format
                addAwsGrant(sg,ruleProto,ruleMinPort,ruleMaxPort,ruleSource,ruleAction,ruleDirection)
        else:
            print "Insufficient info to create rule"
    return True
