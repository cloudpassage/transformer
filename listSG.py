#!/usr/bin/env python

import sys
import boto
import boto.ec2
from aws_ec2 import SecurityGroup

region = None
nameMatch = None
for arg in sys.argv[1:]:
    region = arg

if (region == None):
    conn = boto.connect_ec2()
else:
    conn = boto.ec2.connect_to_region(region)

groups = SecurityGroup.all(conn)
print "loaded %d Security Groups" % len(groups)
for group in groups:
    if (nameMatch != None) and (nameMatch != group.name):
        continue
    print "Security group: %s" % group.to_s()
