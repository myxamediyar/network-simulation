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
    return v

def testRouter(net: Network, nodeName: str, stopTime: int = 10) -> bool:
    prober1 = "prober-" + str(generateRandomID())
    prober2 = "prober-" + str(generateRandomID())
    p1 = generateTrustedNode(net, nodeName, prober1)
    p2 = generateTrustedNode(net, nodeName, prober2)
    testPacket = Packet(prober1, prober2, retransmit=False)
    net.send(testPacket)
    net.updateTickTill(testPacket, DROP, stopTime)
    dropper = net.getNode(nodeName).reportDropHop(testPacket)
    net.removeNode(p1)
    net.removeNode(p2)
    return dropper == None

def identifyDropperBasic(net: Network, packet: Packet, stopTime: int = 100) -> str:
    cur = packet.src
    while cur != None:
        ok = testRouter(net, cur, stopTime)
        cur = net.getNode(cur)
        if not ok: return cur
        cur = cur.reportDropHop(packet)
    # print("This statement should not have been reached!")
    return None

def sendTestPacket(net: Network, srcNode: Router = None, dstNode: Router = None, 
                   tickCount: int = 200, waitDropperTick: int = 100):
    keepSrcNode = srcNode != None
    keepDstNode = dstNode != None
    res = None
    while (res == None):
        srcNode = net.getRandomNode(False) if not keepSrcNode else srcNode
        dstNode = net.getRandomNode(False, invalid=set([srcNode])) if not keepDstNode else dstNode
        testPacket = Packet(srcNode.getName(), dstNode.getName(), logBit=False, retransmit=False)
        net.send(testPacket)
        net.updateTickN(tickCount)
        testPacket.printSummary()
        if (testPacket.getStatus() == DROP):
            res = identifyDropperBasic(net, testPacket, waitDropperTick)
    return res

def sendTestPacketSupervised(gene, net: Network, srcNode: Router, dstNode: Router):
    ok = True
    res = None
    while ok:
        res = next(gene, None)
        if res == None: break     
        testPacket = Packet(srcNode.getName(), dstNode.getName(), logBit=True, retransmit=False)
        net.send(testPacket)
        net.updateTickN(15)
        testPacket.printSummary()
        ok = testPacket.getStatus() == RECV
    return res


def makeSupervisionGene(net: Network, srcNode: Router, dstNode: Router):
    for node in set(net.getNodes()) - set([srcNode, dstNode]):
        l1 = Link(srcNode.getIP(), node.getIP(), 0)
        l2 = Link(dstNode.getIP(), node.getIP(), 0)
        net.setLink(l1)
        net.setLink(l2)
        # net.setLinkWeight((srcNode.getIP(), node.getIP()), 0)
        # net.setLinkWeight((dstNode.getIP(), node.getIP()), 0)
        srcNode.updateRoutingTable()
        node.updateRoutingTable()
        dstNode.updateRoutingTable()
        # srcNode.printNextHop(dstNode.getName())
        yield node
        l1 = Link(srcNode.getIP(), node.getIP(), np.inf)
        l2 = Link(dstNode.getIP(), node.getIP(), np.inf)
        net.setLink(l1)
        net.setLink(l2)
        # net.setLinkWeight((srcNode.getIP(), node.getIP()), np.inf)
        # net.setLinkWeight((dstNode.getIP(), node.getIP()), np.inf)
        node.updateRoutingTable()

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
    print("--------- STARTING PROBE TEST 1: proof of concept ---------")
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
    print("--------- ENDING PROBE TEST 1: -------------------------")

def probe_test2(): #randomized probing in desne networks
    nodes, d = generateConnectedRandomGraph(101, 10, 0.8)
    net = Network(50)
    net.changeTopology_nnal(nodes, d)
    maliciousNode = Attacker('node-mal', 40)
    net.addNode(maliciousNode)
    net.triggerNodesExplore()
    print("\nDropper identified to be:", sendTestPacket(net))

def probe_test3(): #supervisory node
    nodes, d = generateConnectedRandomGraph(20, 10, 0.5)
    net = Network(10)
    net.changeTopology_nnal(nodes, d)
    #malicious node installed
    maliciousNode = Attacker('node-mal')
    net.addNode(maliciousNode)
    #superviory node installed 
    supervisor1 = Defender("supervisor1", np.inf)
    net.addNode(supervisor1)
    supervisor2 = Defender("supervisor2", np.inf)
    net.addNode(supervisor2)
    net.triggerNodesExplore()
    geneRun = makeSupervisionGene(net, supervisor1, supervisor2)
    print("\nDropper identified to be:", sendTestPacketSupervised(geneRun, net, supervisor1, supervisor2))

probe_test1()
probe_test2()
probe_test3()

