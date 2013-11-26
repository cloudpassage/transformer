#!/usr/bin/env python

import sys
import os.path
import boto
import boto.ec2

#default settings
verbose = False
region = None
nameMatch = None
groupBy = "SG"

# New functionality:
# Currently the program prints out one line per EC2 instance, even if they
# have the same security group. Can we do the following?
# *  For each security group, print all the EC2 instances that use it.
# *  For each EC2 instance, print all the security groups applied to it.
# It would have to be per AWS region since security groups don't cross
# regions.

# Possible formats:
# "EC2"
# Region: <region-name>
#   Instance: <instance-name>
#     Security Group: <group-name>
# "SG"
# Region: <region-name>
#   Security Group: <group-name>
#     Instance: <instance-name>

def processCommandLineArgs(args):
    global region, nameMatch, verbose, groupBy
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
            region = arg[9:]
        elif arg.startswith("--allregions") or arg.startswith("--all"):
            region = "ALL"
        elif (arg == "--groupBy=EC2"):
            groupBy = "EC2"
        elif (arg == "--groupBy=SG"):
            groupBy = "SG"
        elif arg.startswith("--platform="):
            platform = arg[11:]
            if not ((platform == "windows") or (platform == "linux") or (platform == "all")):
                print >> sys.stderr, "Illegal platform: %s" % platform
                ok = False
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
    # print >> sys.stderr, "--group=<name>\t\tSpecify name of an EC2-Classic or EC2-VPC Security Group (SG) to print"
    print >> sys.stderr, "--region=<name>\t\tSpecify an AWS region, prints all Security Groups in that region"
    print >> sys.stderr, "--allregions\t\tSpecifies all AWS regions, to have their Security Groups printed"
    print >> sys.stderr, "--groupBy=EC2\t\tShow all EC2 instances, and security groups attached to each"
    print >> sys.stderr, "--groupBy=SG\t\tShow all Security Groups, and instances using each SG"


def dump_regions(conn,verbose):
    regions = conn.get_all_regions()
    if (verbose):
        for region in regions:
            print "Region: %s" % region.name
    return regions


def get_instance_name(instance):
    name = instance.dns_name
    if (name == None) or (len(name) < 1):
        name = instance.public_dns_name
        if (name == None) or (len(name) < 1):
            name = instance.ip_address
            if (name == None) or (len(name) < 1):
                name = instance.private_dns_name
                if (name == None) or (len(name) < 1):
                    name = instance.id
    return name


def dump_instance(prefix,instance):
    name = get_instance_name(instance)
    vpc_info = ""
    if (instance.vpc_id != None) and (len(instance.vpc_id) > 0):
        vpc_info = " (VPC: %s)" % instance.vpc_id
    print "%sInstance: %s%s" % (prefix, name, vpc_info)


def dump_instances_by_ec2(conn):
    reservations = conn.get_all_instances()
    for reservation in reservations:
        for instance in reservation.instances:
            dump_instance("  ",instance)
            for group in reservation.groups:
                print "    Security Group: %s" % group.name


def dump_instances_by_sg(conn):
    reservations = conn.get_all_instances()
    group_list = {}
    for reservation in reservations:
        group_name_list = ""
        for group in reservation.groups:
            group_name_list += " %s" % group.name
            if not (group.name in group_list):
                group_list[group.name] = []
        for instance in reservation.instances:
            for group in reservation.groups:
                group_list[group.name].append(instance)
    group_names = group_list.keys()
    group_names.sort()
    for gname in group_names:
        instList = group_list[gname]
        print "  Security Group: %s" % gname
        for instance in instList:
            dump_instance("    ",instance)


def dump_instances(conn,formatType):
    if formatType == "EC2":
        dump_instances_by_ec2(conn)
    elif formatType == "SG":
        dump_instances_by_sg(conn)
    else:
        print >> sys.stderr, "Unrecognized format: %s" % formatType


# begin main in-line code
processCommandLineArgs(sys.argv[1:])

if (region == None):
    conn = boto.connect_ec2()
    dump_regions(conn,True)
    print " "
    print "Default Region:"
    dump_instances(conn,groupBy)
elif (region == "ALL"):
    conn = boto.connect_ec2()
    regions = dump_regions(conn,False)
    for region in regions:
        print "Region: %s" % region.name
        conn = boto.ec2.connect_to_region(region.name)
        dump_instances(conn,groupBy)
else:
    conn = boto.ec2.connect_to_region(region)
    print "Region: %s" % region
    dump_instances(conn,groupBy)
