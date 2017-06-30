#!/usr/bin/python
__author__ = "rootM"

from pox.core import core
import pox.openflow.libopenflow_01 as of
import threading
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import *
import csv
import os
from pox.openflow.of_json import *
from influxdb import InfluxDBClient
import logging
import time

logging.getLogger("urllib3").setLevel(logging.WARNING)
log = core.getLogger()
networkStats = {}
blockedFbUsers = []
allowedFbUsers = []
blockedYouUsers = []
allowedYouUsers = []
allowedUsers = []
blockedUsers = []
blockedPorts = {}
limitedUsers = []
test = {}
bandwidth = {}


class Firewall(EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        log.info("Enabling Firewall Module")
        do_every(1, _request_flows)


def _getHostMacs(stats):
    hosts = []
    for i in stats:
        for j in i.keys():
            if j == 'match':
                print j
                if i[j]['dl_src'] not in hosts and i[j]['dl_src'] is not None:
                    hosts.append(i[j]['dl_src'])
                if i[j]['dl_dst'] not in hosts and i[j]['dl_dst'] is not None:
                    hosts.append(i[j]['dl_dst'])
    return hosts


def _deleteFlows(f):
    msg_del_flow = of.ofp_flow_mod()
    msg_del_flow.match = f.match
    msg_del_flow.command = of.OFPFC_DELETE
    return msg_del_flow


def _addMacFlows(f, ip=False, port=False, flow=False, p=None):
    # now install firewall flow for 5 seconds
    msg = of.ofp_flow_mod()
    if not port:
        msg.match = f.match
    if ip:
        msg.match.dl_type = 2048
        msg.match.nw_dst = f.match.nw_dst
    if port:
        #msg.match.dl_src = f.match.dl_dst
        msg.match.dl_dst = f.match.dl_dst
        msg.match.dl_type = f.match.dl_type
        msg.match.nw_proto = f.match.nw_proto
        msg.match.nw_dst = f.match.nw_dst
        msg.match.tp_dst = int(p)
    msg.priority = 65535
    msg.hard_timeout = 0
    if flow:
        #print "Output is %s" % f.actions[0].port
        msg.actions.append(of.ofp_action_output(port=f.actions[0].port))
    else:
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
    return msg


def _readFile(file):
    f = open(file, "r")
    subnets = []
    for line in f:
        subnets.append(line.strip("\n"))
    return subnets


def _parseAddr(i):
    classAddr = IPAddr(i)
    ip = classAddr.toStr()
    return ip, classAddr


def newStats(f, delete=False, count=0, limit=None):
    if delete:
        test[f.match.dl_src].insert(0, 1)
    else:
        if test[f.match.dl_src][0] != 1:
            if count == 0 and f.priority != 65535:
                test[f.match.dl_src][0] = f.byte_count
            elif count != 0 and f.priority != 65535:
                test[f.match.dl_src][0] += f.byte_count
        else:
            test[f.match.dl_src][0] = 0
        if f.match.dl_src not in bandwidth.keys() and limit is not None:
            bandwidth[f.match.dl_src] = '0'
        bandwidth[f.match.dl_src] = str(
        100 * sum(test[f.match.dl_src]) / limit) + '%'
    if f.match.dl_src not in networkStats.keys():
        networkStats[f.match.dl_src] = 0
    networkStats[f.match.dl_src] = sum(test[f.match.dl_src])


def _handleFlowStatsReceived(event):
    global networkStats
    global blockedFbUsers
    global allowedFbUsers
    global blockedYouUsers
    global allowedYouUsers
    global allowedUsers
    global blockedUsers
    global blockedPorts
    global test
    global limitedUsers
    global bandwidth
    count = {}
    fbSubnets = _readFile("fb_subnets.txt")
    youSubnets = _readFile("you_subnets.txt")
    stats = flow_stats_to_list(event.stats)
#    print stats
#    hosts = _getHostMacs(stats)
#    print hosts
    for f in event.stats:
        if f.match.dl_src not in count.keys():
            count[f.match.dl_src] = 0

        if f.match.dl_src not in test.keys():
            client = influxInit()
            json_user = [{"measurement": "UserInfo",
                          "tags": {"host": f.match.dl_src},
                          "fields": {"permission": "N/A",
                                     "limit": 10000,
                                     "facebook": 'Allow',
                                     "youtube": 'Allow',
                                     "ports": 'n/a'}}]
            client.write_points(json_user)
            test[f.match.dl_src] = [0]

        host_s, limit_s, permission_s, facebook_s, youtube_s, ports_s = queryData(
            f.match.dl_src)
        host_d, limit_d, permission_d, facebook_d, youtube_d, ports_d = queryData(
            f.match.dl_dst)
#        print (host_src, limit, permission, facebook, youtube, ports)
        if host_s == f.match.dl_src and f.match.dl_type == 2048:
            if permission_s == 'Block':
                if f.match.dl_src not in blockedUsers:
                    print "BLOCK HOST:%s" % f.match.dl_src
                    blockedUsers.append(f.match.dl_src)
                    newStats(f, delete=True)
                    msg_del = _deleteFlows(f)
                    event.connection.send(msg_del)
                    msg = _addMacFlows(f)
                    event.connection.send(msg)
                    if f.match.dl_src in allowedUsers:
                        allowedUsers.remove(f.match.dl_src)

            elif permission_s == 'Bypass':
                if f.match.dl_src not in allowedUsers:
                    print "ALLOW HOST:%s" % f.match.dl_src

                    allowedUsers.append(f.match.dl_src)
                    newStats(f, delete=True)
                    msg_del = _deleteFlows(f)
                    event.connection.send(msg_del)
                    if f.match.dl_src in blockedUsers:
                        blockedUsers.remove(f.match.dl_src)
            else:
                if f.match.dl_src in allowedUsers:
                    allowedUsers.remove(f.match.dl_src)
                    newStats(f, delete=True)
                    msg_del = _deleteFlows(f)
                    event.connection.send(msg_del)
                if f.match.dl_src in blockedUsers:
                    newStats(f, delete=True)
                    msg_del = _deleteFlows(f)
                    event.connection.send(msg_del)
                    blockedUsers.remove(f.match.dl_src)
                if facebook_s == "Block":
                    if f.match.dl_src not in blockedFbUsers and f.match.dl_type == 2048:
                        if f.match.nw_dst is not None:
                            ip, ipAddr = _parseAddr(f.match.nw_dst)
                            for net in fbSubnets:
                                if ipAddr.in_network(net) is True:
                                    if f.match.dl_src not in blockedFbUsers:
                                        blockedFbUsers.append(f.match.dl_src)
                                        print "BLOCKING FACEBOOK FOR HOST: %s" % f.match.dl_src
                                        newStats(f, delete=True)
                                        msg_del = _deleteFlows(f)
                                        event.connection.send(msg_del)
                                        msg = _addMacFlows(f)
                                        event.connection.send(msg)
                    if f.match.dl_src in allowedFbUsers:
                        allowedFbUsers.remove(f.match.dl_src)
                elif facebook_s == "Allow":
                    if f.match.dl_src not in allowedFbUsers:
                        allowedFbUsers.append(f.match.dl_src)
                    if f.match.dl_src in blockedFbUsers:
                        #print f.match.dl_src
                        ip, ipAddr = _parseAddr(f.match.nw_dst)
                        for net in fbSubnets:
                            if ipAddr.in_network(net) is True:
                                print "ALLOWING FACEBOOK FOR HOST: %s" % f.match.dl_src
                                if f.match.dl_src in blockedFbUsers:
                                    blockedFbUsers.remove(f.match.dl_src)
                                    print "Removed the fb user"
                                newStats(f, delete=True)
                                msg_del = _deleteFlows(f)
                                event.connection.send(msg_del)

                if youtube_s == "Block":
                    #print "host:%s , perm:%s" % (f.match.dl_src, youtube_s)
                    if f.match.dl_src not in blockedYouUsers and f.match.dl_type == 2048:
                        if f.match.nw_dst is not None:
                            ip, ipAddr = _parseAddr(f.match.nw_dst)
                            for net in youSubnets:
                                if ipAddr.in_network(net) is True:
                                    if f.match.dl_src not in blockedYouUsers:
                                        blockedYouUsers.append(f.match.dl_src)
                                        print "BLOCKING YOUTUBE FOR HOST: %s" % f.match.dl_src
                                        print "host:%s" %f.match.dl_src
                                        newStats(f, delete=True)
                                        msg_del = _deleteFlows(f)
                                        event.connection.send(msg_del)
                                        msg = _addMacFlows(f)
                                        event.connection.send(msg)
                    if f.match.dl_src in allowedYouUsers:
                        allowedYouUsers.remove(f.match.dl_src)
                elif youtube_s == "Allow":
                    #print "host :%s, %s... %s" % (f.match.dl_src, youtube_s, allowedYouUsers)
                    if f.match.dl_src not in allowedYouUsers:
                        allowedYouUsers.append(f.match.dl_src)
                    if f.match.dl_src in blockedYouUsers:
                        #print f.match.dl_src
                        ip, ipAddr = _parseAddr(f.match.nw_dst)
                        for net in youSubnets:
                            if ipAddr.in_network(net) is True:
                                print "ALLOWING YOUTUBE FOR HOST: %s" % f.match.dl_src
                                if f.match.dl_src in blockedYouUsers:
                                    blockedYouUsers.remove(f.match.dl_src)
                                    print "Removed the youtube user"
                                newStats(f, delete=True)
                                msg_del = _deleteFlows(f)
                                event.connection.send(msg_del)

                if sum(test[f.match.dl_src]
                       ) > limit_s and f.match.dl_src not in limitedUsers:

                    print (
                        "SWITCH",
                        event.connection.dpid,
                        "BYTES EXCEEDED FIREWALL LIMIT",
                        f.byte_count)
                    # now install firewall flows
                    newStats(f, delete=True)
                    msg_del = _deleteFlows(f)
                    event.connection.send(msg_del)
                    msg = _addMacFlows(f)
                    event.connection.send(msg)
                    limitedUsers.append(f.match.dl_src)

                elif sum(test[f.match.dl_src]) < limit_s and f.match.dl_src in limitedUsers:
                    newStats(f, delete=True)
                    msg_del = _deleteFlows(f)
                    event.connection.send(msg_del)
                    limitedUsers.remove(f.match.dl_src)

                else:
                    #                    print "No Limitations Yet"
                    pass
#        print "Dst dl: %s, host: %s" % (f.match.dl_dst, host)
        if host_d == f.match.dl_dst and f.match.dl_type == 2048:
            # print "Entering new condition"
            if ports_d != 'n/a':
                for p in ports_d:
                    #                   print "PORTS TO BLOCK: %s" % p
                    if f.match.dl_dst not in blockedPorts.keys():
                        blockedPorts[f.match.dl_dst] = []

                    if p not in blockedPorts[f.match.dl_dst]:
                        # print "Dst port: %s, %s, %s" % (f.match.tp_dst,
                        # f.match.tp_src, f.match.dl_dst)
                        if f.match.tp_dst == int(p):
                            print "BLOCKING PORTS: %s" % p
                            #msg_del = _deleteFlows(f)
                            # event.connection.send(msg_del)
                            msg = _addMacFlows(f, port=True, p=p)
                            event.connection.send(msg)
                            blockedPorts[f.match.dl_dst].append(p)
                for pp in blockedPorts[f.match.dl_dst]:
                    if pp not in ports_d:
                        print "port: %s exists so remove it!" % pp
                        blockedPorts[f.match.dl_dst].remove(pp)
                        msg_del = _deleteFlows(f)
                        event.connection.send(msg_del)

            else:
                #                print "We have no ports to block!"
                if f.match.dl_dst in blockedPorts.keys() and len(
                        blockedPorts[f.match.dl_dst]) > 0:
                    #                    print "Lets unblock the ports"
                    if f.match.tp_dst is not None:
                        blockedPorts[f.match.dl_dst] = []
                        msg_del = _deleteFlows(f)
                        event.connection.send(msg_del)
#                   msg = _addMacFlows(f, port=True, flow=True)
#                   event.connection.send(msg)
                        print "ALLOW THE SPECIFIED PORTS"

        if f.match.dl_type == 2048:
            newStats(f, count=count[f.match.dl_src], limit=limit_s)
            count[f.match.dl_src] += 1
    client = influxInit()
    storeStats(test, client, bandwidth)
    time.sleep(0.5)
    print "-------------------------------"
    print "NetworkStats = %s" % bandwidth
    print "-------------------------------"
    print "Allowed Users: %s" % allowedUsers
    print "Allowed FB Users: %s" % allowedFbUsers
    print "Allowed YOUTUBE Users: %s" % allowedYouUsers
    print "Blocked Users: %s" % blockedUsers
    print "Blocked FB Users: %s" % blockedFbUsers
    print "blocked YOUTUBE Users: %s" % blockedYouUsers
    print "Blocked Ports: %s" % blockedPorts
    print "Limited Users: %s" % limitedUsers
    print "-------------------------------"


def influxInit():
    db_list = []
    client = InfluxDBClient(
        host='127.0.0.1',
        port=8086,
        username='root',
        password='root',
        database='networkStats')
    dbs = client.get_list_database()
    for db in dbs:
        db_list.append(db["name"])

    if "networkStats" not in db_list:
        client.create_database('networkStats')
    return client


def queryData(f):
    parameters = {}
    client = influxInit()
    if f is not None:
        rs = client.query("select last(*) from UserInfo where host='%s';" % f)
    else:
        rs = client.query("select last(*) from UserInfo;")
#    print list(rs.get_points(measurement='UserInfo'))[0].keys()
    for item in list(rs.get_points(measurement='UserInfo'))[0].keys():
        if item == 'last_ports':
            if list(rs.get_points(measurement='UserInfo'))[0][item] != 'n/a':
                ports = list(rs.get_points(measurement='UserInfo'))[
                    0][item].split(",")
            else:
                ports = 'n/a'
            parameters[item] = ports

        else:
            parameters[item] = list(
                rs.get_points(
                    measurement='UserInfo'))[0][item]
    host = f
    return host, parameters["last_limit"], parameters["last_permission"], parameters[
        "last_facebook"], parameters["last_youtube"], parameters["last_ports"]


def storeStats(test, client, bandwidth):
    json_body = [{"measurement": "BandwidthUsage",
                  "tags": {}, "fields": {}}]
#    client = influxInit()
    for k in test.keys():
        json_body[0]['tags']['host'] = k
        json_body[0]['fields']['Bytes'] = sum(test[k])
        json_body[0]['fields']['Percentage'] = bandwidth[k]
        client.write_points(json_body)


def do_every(interval, workerFunc, iterations=0):
    if iterations != 1:
        threading.Timer(
            interval, do_every, [
                interval, workerFunc, 0 if iterations == 0 else iterations - 1]).start()
    workerFunc()


def _request_flows():
    for req in core.openflow._connections.values():
        req.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
        req.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))


def launch():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
    core.openflow.addListenerByName(
        "FlowStatsReceived",
        _handleFlowStatsReceived)
