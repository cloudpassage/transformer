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
destName = None
destPrefix = None
destRegion = None
ignoreDefault = True
platform = "linux"

def processCmdLineArgs(args):
    global nameMatch, authFile, verbose, destRegion, destName, destPrefix
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
            destRegion = arg[9:]
        elif arg.startswith("--dest="):
            destName = arg[7:]
        elif arg.startswith("--destprefix="):
            destPrefix = arg[13:]
        elif arg.startswith("--policy="):
            nameMatch = arg[9:]
        else:
            print >> sys.stderr, "Unknown argument: %s" % arg
            ok = False
    if (not ok):
        sys.exit(1)

def printUsage(progName):
    print >> sys.stderr, "Usage: %s [<flag> [<flag>]...]" % progName
    print >> sys.stderr, "Where <flag> is one of:"
    print >> sys.stderr, "-?\t\t\tThis message"
    print >> sys.stderr, "-v\t\t\tMake program verbose"
    print >> sys.stderr, "--auth=<file>\t\tSpecify a file containing your Halo API key"
    print >> sys.stderr, "--policy=<name>\t\tSpecify name of a Halo Firewall Policy (FWP) to convert"
    print >> sys.stderr, "--region=<name>\t\tSpecify an AWS region, copies policy/policies to that region"
    print >> sys.stderr, "--dest=<name>\t\tIf copying single FWP, specify name of copied Security Group"
    print >> sys.stderr, "--destprefix=<string>\tWhen copying each FWP, add prefix to name of each SG"


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


#
# End of Functions, beginning of in-line main code
#
progDir = os.path.dirname(sys.argv[0])
processCmdLineArgs(sys.argv[1:])
transformer.verbose = verbose

if (destRegion == None):
    ec2Conn = boto.connect_ec2()
else:
    ec2Conn = boto.ec2.connect_to_region(destRegion)
    print "Copying to region: %s" % destRegion
haloConn = getHaloConnection(authFile,progDir)

policies = cputils.getFirewallPolicyList(haloConn)
print "loaded %d Firewall Policies" % len(policies)
for policy in policies:
    if (nameMatch != None) and (nameMatch != policy['name']):
        continue
    if ignoreDefault and (nameMatch == None) and (policy['name'].lower() == "default"):
        continue
    print "Converting firewall policy: %s" % policy['name']

    destGroupName = policy['name']
    if (destName != None):
        destGroupName = destName
    elif (destPrefix != None):
        destGroupName = destPrefix + policy['name']
    print "  Destination SG: %s" % destGroupName
    transformer.convertFirewallPolicyToSecurityGroup(haloConn,ec2Conn,policy,destGroupName)
