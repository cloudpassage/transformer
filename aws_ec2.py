#!/usr/bin/env python

class SecurityGrant:
    def __init__(self, cidr_ip, name, owner_id):
        self.cidr_ip = cidr_ip
        self.name = name
        self.owner_id = owner_id

    def to_s(self):
        if self.cidr_ip == None:
            return "name=%s owner=%s" % (self.name, self.owner_id)
        else:
            return "ip=%s" % self.cidr_ip

class SecurityRule:
    def __init__(self, ip_protocol, from_port, to_port, inbound = True):
        self.grants = []
        self.ip_protocol = ip_protocol
        self.from_port = from_port
        self.to_port = to_port
        self.inbound = inbound

    def addGrant(self, cidr):
        self.grants.append(cidr)

    def to_s(self):
        if (self.inbound):
            direction = "inbound"
        else:
            direction = "outbound"
        s = "allow %s-%s/%s %s" % (self.from_port, self.to_port, self.ip_protocol, direction)
        for grant in self.grants:
            s += "\n    Zone: %s" % grant.to_s()
        return s

class SecurityGroup:
    def __init__(self, name, description):
        self.rules = []
        self.name = name
        self.description = description
        self.is_vpc = False

    def addRule(self, rule):
        self.rules.append(rule)

    def to_s(self):
        s = "%s" % self.name
        if (self.description != None):
            s += "\n  Descr: %s" % self.description
        for rule in self.rules:
            s += "\n  Rule: %s" % rule.to_s()
        return s

    @staticmethod
    def all(ec2_conn):
        list = []
        results = ec2_conn.get_all_security_groups()
        for group in results:
            sg = SecurityGroup(group.name,group.description)
            for rule in group.rules:
                sr = SecurityRule(rule.ip_protocol,rule.from_port,rule.to_port)
                for grant in rule.grants:
                    gr = SecurityGrant(grant.cidr_ip,grant.name,grant.owner_id)
                    sr.addGrant(gr)
                sg.addRule(sr)
            for rule in group.rules_egress:
                sg.is_vpc = True
                sr = SecurityRule(rule.ip_protocol,rule.from_port,rule.to_port,False)
                for grant in rule.grants:
                    gr = SecurityGrant(grant.cidr_ip,grant.name,grant.owner_id)
                    sr.addGrant(gr)
                sg.addRule(sr)
            list.append(sg)
        return list
