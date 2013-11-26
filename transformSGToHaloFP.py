#!/usr/bin/env python

import sys
import os.path
import boto
import boto.ec2
from aws_ec2 import SecurityGroup
import cpapi
import cputils
import transformer

nameMatch = None
authFile = "transform.auth"
verbose = False
regionToCopy = None
destName = None
destPrefix = None
ignoreDefault = False
platform = "linux"

def processCmdLineArgs(args):
    global nameMatch, authFile, verbose, regionToCopy, destName, destPrefix, platform
    ok = True
    for arg in args:
        if ((arg == '-?') or (arg == "-h")):
            printUsage(os.path.basename(sys.argv[0]))
            return sys.exit(0)
        elif arg.startswith("--auth="):
            authFile = arg[7:]
        elif (arg == "-v") or (arg == "--verbose"):
            verbose = True
        elif arg.startswith("--region="):
            regionToCopy = arg[9:]
        elif arg.startswith("--allregions") or arg.startswith("--all"):
            regionToCopy = "ALL"
        elif arg.startswith("--dest="):
            destName = arg[7:]
        elif arg.startswith("--destprefix="):
            destPrefix = arg[13:]
        elif arg.startswith("--group="):
            nameMatch = arg[8:]
        elif arg.startswith("--platform="):
            platform = arg[11:]
            if not ((platform == "windows") or (platform == "linux") or (platform == "all")):
                print >> sys.stderr, "Illegal platform: %s" % platform
                ok = False
        else:
            print >> sys.stderr, "Unknown argument: %s" % arg
            ok = False
    if (nameMatch == None) and (regionToCopy == None):
        print >> sys.stderr, "You must specify either --group or --region"
        printUsage(os.path.basename(sys.argv[0]))
        ok = False
    if (nameMatch == None) and (destName != None):
        print >> sys.stderr, "You cannot specify both --region and --dest ..."
        print >> sys.stderr, "When copying all groups in a region, we cannot rename them all to the same name"
        ok = False
    if (not ok):
        sys.exit(1)

def printUsage(progName):
    print >> sys.stderr, "Usage: %s [<flag> [<flag>]...]" % progName
    print >> sys.stderr, "Where <flag> is one of:"
    print >> sys.stderr, "-?\t\t\tThis message"
    print >> sys.stderr, "-v\t\t\tMake program verbose"
    print >> sys.stderr, "--auth=<file>\t\tSpecify a file containing your Halo API key"
    print >> sys.stderr, "--group=<name>\t\tSpecify name of an EC2-Classic or EC2-VPC Security Group (SG) to convert"
    print >> sys.stderr, "--region=<name>\t\tSpecify an AWS region, converts all Security Groups in that region"
    print >> sys.stderr, "--allregions\t\tSpecifies all AWS regions, to have their Security Groups converted"
    print >> sys.stderr, "--dest=<name>\t\tIf copying single SG, specify name of copied Policy"
    print >> sys.stderr, "--destprefix=<string>\tWhen copying each SG, add prefix to name of each Policy"
    print >> sys.stderr, "--platform=<name>\tSets platform for Halo policy, can be 'linux', 'windows', or 'all'"


def getHaloConnection(authFilename,progDir):
    credentials = cputils.processAuthFile(authFilename,progDir)
    credential = credentials[0][0]
    haloConn = cpapi.CPAPI()
    (haloConn.key_id, haloConn.secret) = (credential['id'], credential['secret'])
    if ((not haloConn.key_id) or (not haloConn.secret)):
        print >> sys.stderr, "Unable to read auth file %s. Exiting..." % authFilename
        print >> sys.stderr, "Requires lines of the form \"<API-id>|<secret>\""
        sys.exit(1)
    resp = haloConn.authenticateClient()
    if (not resp):
        # no error message here, rely on cpapi.authenticate client for error message
        sys.exit(1)
    return haloConn


def createGroupPrefix(regionName,group):
    # s = regionName.replace("-","") + "-"
    s = regionName + "-"
    if (group.is_vpc):
        s += "vpc-"
    return s


def convertSecurityGroup(haloConn,group,destGroupName,platform):
    oldFwp = cputils.findFirewallPolicyByName(haloConn,destGroupName)
    if (oldFwp != None):
        print >> sys.stderr, "Found existing Firewall Policy with name: %s" % destGroupName
        print >> sys.stderr, "  Group may have already been converted... skipping"
    else:
        transformer.convertSecurityGroupToHalo(haloConn,group,destGroupName,platform)


def convertRegion(ec2Conn,haloConn,nameMatch,regionName):
    groups = SecurityGroup.all(ec2Conn)
    print "loaded %d Security Groups" % len(groups)
    for group in groups:
        if (nameMatch != None) and (nameMatch != group.name):
            continue
        if ignoreDefault and (nameMatch == None) and (group.name.lower() == "default"):
            continue
        print "Converting security group: %s" % group.name

        destGroupName = group.name
        if (destName != None):
            destGroupName = destName
        elif (destPrefix != None):
            destGroupName = destPrefix + group.name
        elif (regionName != None):
            destGroupName = createGroupPrefix(regionName,group) + group.name
        if (platform == "all"):
            for myPlatform in ['linux', 'windows']:
                convertSecurityGroup(haloConn,group,destGroupName + "-" + myPlatform,myPlatform)
        else:
            convertSecurityGroup(haloConn,group,destGroupName,platform)


#
# End of Functions, beginning of in-line main code
#
transformer.verbose = verbose
progDir = os.path.dirname(sys.argv[0])
processCmdLineArgs(sys.argv[1:])

haloConn = getHaloConnection(authFile,progDir)

if (regionToCopy == None):
    ec2Conn = boto.connect_ec2()
    convertRegion(ec2Conn,haloConn,nameMatch,None)
elif (regionToCopy == "ALL"):
    ec2Conn = boto.connect_ec2()
    regions = ec2Conn.get_all_regions()
    for region in regions:
        ec2Conn = boto.ec2.connect_to_region(region.name)
        convertRegion(ec2Conn,haloConn,nameMatch,region.name)
else:
    ec2Conn = boto.ec2.connect_to_region(regionToCopy)
    convertRegion(ec2Conn,haloConn,nameMatch,regionToCopy)
