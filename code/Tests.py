from NetworkObjects import *
from RoutingAlgos import *
import numpy as np

def setupBasic():
    nodes = ['a', 'b', 'c', 'd', 'e']
    d = {}
    d[nodes[0]] = [(nodes[1], 1), (nodes[2], 3)]
    d[nodes[1]] = [(nodes[2], 1), (nodes[3], 3)]
    d[nodes[2]] = [(nodes[3], 1)]
    d[nodes[3]] = [(nodes[4], 1)]
    return nodes, d

def test1():
    nodes, d = setupBasic()
    net = Network(40)
    net.changeTopology_nnal(nodes, d)
    testPacket = Packet("a", "e", True)
    net.send(testPacket)
    net.updateTickN(100)
    testPacket.printSummary()

def test2():
    nodes, d = setupBasic()
    net = Network(40)
    net.changeTopology_nnal(nodes, d)
    ip1 = net.getIP('d')
    ip2 = net.getIP('e')
    net.setLinkWeight((ip1, ip2), np.inf)
    testPacket = Packet("a", "e", True)
    net.send(testPacket)
    net.updateTickN(100)
    testPacket.printSummary()

def test3():
    nodes, d = setupBasic()
    net = Network(40)
    net.changeTopology_nnal(nodes, d)
    maliciousNode = Attacker('d')
    net.setNode(maliciousNode)
    testPacket = Packet("a", "e", True)
    net.send(testPacket)
    net.updateTickN(100)
    testPacket.printSummary()


test3()


#TODO : packet not nodes but IPs
