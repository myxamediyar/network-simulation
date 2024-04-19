from NetworkObjects import *
from RoutingAlgos import *
import numpy as np
import random

def setupBasic():
    nodes = ['a', 'b', 'c', 'd', 'e']
    d = {}
    d[nodes[0]] = [(nodes[1], 1), (nodes[2], 3)]
    d[nodes[1]] = [(nodes[2], 1), (nodes[3], 3)]
    d[nodes[2]] = [(nodes[3], 1)]
    d[nodes[3]] = [(nodes[4], 1)]
    return nodes, d


def generateConnectedRandomGraph(n, maxW=10, connectivity=0.3):
    nodes = ["node" + str(i) for i in range(n)]
    d = defaultdict(list)

    # d = {}

    # for v in nodes:
    #     d[v] = []

    connected = [nodes[0]]
    for v in nodes[1:]:
        connectTo = random.choice(connected)
        w = random.randint(1, maxW)
        d[connectTo].append((v, w))
        connected.append(v)

    for i in range(n):
        for j in range(n):
            if i != j and (nodes[j], any(x[0] == nodes[j] for x in d[nodes[i]])) and random.random() < connectivity:
                w = random.randint(1, maxW)
                d[nodes[i]].append((nodes[j], w))

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
    # print("This statement should not have been reached!")
    return None

def test1(): #basic: should complete round trip
    nodes, d = setupBasic()
    net = Network(40)
    net.changeTopology_nnal(nodes, d)
    testPacket = Packet("a", "e", True)
    net.send(testPacket)
    net.updateTickN(100)
    testPacket.printSummary()

def test2(): #basic: should drop
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

def test3(): #should report drop (unknown reasons)
    nodes, d = setupBasic()
    net = Network(40)
    net.changeTopology_nnal(nodes, d)
    maliciousNode = Attacker('d')
    net.setNode(maliciousNode)
    testPacket = Packet("a", "e", True)
    net.send(testPacket)
    net.updateTickN(100)
    testPacket.printSummary()

def probe_test1(): #proof of concept probing
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
    print("\nDropper identified to be:", res)

def probe_test2(): #randomized probing in desne networks
    nodes, d = generateConnectedRandomGraph(101, 10, 0.8)
    net = Network(50)
    net.changeTopology_nnal(nodes, d)
    maliciousNode = Attacker('node-mal')
    net.addNode(maliciousNode)
    for _ in range(5):
        net.addLink(Link(maliciousNode.getIP(), net.getIP("node" + str(random.randint(0, 100))), 0))
    net.triggerNodesExplore()
    res = None
    while (res == None):
        srcNode = random.randint(0, 100)
        destNode = srcNode
        while destNode == srcNode:
            destNode = random.randint(0, 100)
        testPacket = Packet("node" + str(srcNode), "node" + str(destNode), logBit=False, retransmit=False)
        net.send(testPacket)
        net.updateTickN(200)
        testPacket.printSummary()
        if (testPacket.getStatus() == DROP):
            res = identifyDropperBasic(net, testPacket)
    print("\nDropper identified to be:", res)

def probe_test3(): #supervisory node
    nodes, d = generateConnectedRandomGraph(101, 10, 0.8)
    net = Network(50)
    net.changeTopology_nnal(nodes, d)
    #malicious node installed
    maliciousNode = Attacker('node-mal')
    net.addNode(maliciousNode)
    for _ in range(5):
        net.addLink(Link(maliciousNode.getIP(), net.getIP("node" + str(random.randint(0, 100))), 0))
    #superviory node installed 
    supervisor = Router("supervisor")
    net.addLink(Link(supervisor.getIP(), net.getIP("node-mal"), 0))
    for i in range(101):
        net.addLink(Link(supervisor.getIP(), net.getIP("node" + str(i)), 0))
    net.triggerNodesExplore()
    res = None
    while (res == None):
        srcNode = random.randint(0, 100)
        destNode = srcNode
        while destNode == srcNode:
            destNode = random.randint(0, 100)
        testPacket = Packet("node" + str(srcNode), "node" + str(destNode), logBit=False, retransmit=False)
        net.send(testPacket)
        net.updateTickN(200)
        testPacket.printSummary()
        if (testPacket.getStatus() == DROP):
            res = identifyDropperBasic(net, testPacket)
    print("\nDropper identified to be:", res)

# probe_test1()
# probe_test2()

