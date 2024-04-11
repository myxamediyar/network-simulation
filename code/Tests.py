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

def generateTrustedNode(net: Network, to: str, name: str):
    v = Router(name)
    u = net.getNode(to)
    l = Link(v.getIP(), u.getIP(), 0)
    net.addNode(v)
    net.addLink(l)
    u.updateRoutingTable()
    v.updateRoutingTable()
    return v

def testRouter(net: Network, nodeName: str) -> bool:
    prober1 = "prober-" + str(generateRandomID())
    prober2 = "prober-" + str(generateRandomID())
    p1 = generateTrustedNode(net, nodeName, prober1)
    p2 = generateTrustedNode(net, nodeName, prober2)
    p1.updateRoutingTable()
    p2.updateRoutingTable()
    testPacket = Packet(prober1, prober2, retransmit=False)
    net.send(testPacket)
    net.updateTickTill(testPacket, DROP)
    dropper = net.getNode(nodeName).reportDropHop(testPacket)
    net.removeNode(p1)
    net.removeNode(p2)
    return dropper == None


def identifyDropperBasic(net: Network, packet: Packet) -> str:
    cur = packet.src
    while cur != None:
        ok = testRouter(net, cur)
        cur = net.getNode(cur)
        if not ok: return cur
        cur = cur.reportDropHop(packet)
    print("This statement should not have been reached!")
    return None

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

def probe_test1():
    #proof of concept
    nodes, d = setupBasic()
    net = Network(40)
    net.changeTopology_nnal(nodes, d)
    maliciousNode = Attacker('d')
    net.setNode(maliciousNode)
    testPacket = Packet("a", "e", logBit=True, retransmit=False)
    net.send(testPacket)
    net.updateTickN(100)
    testPacket.printSummary()
    res = identifyDropperBasic(net, testPacket)
    print("Dropper identified to be:", res)


probe_test1()

