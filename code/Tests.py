from debugpy import connect
from NetworkObjects import *
from RoutingAlgos import *
import numpy as np
import random

TEST_MSG_LEN = 70
TEST_MSG_BUFFER = 14

def startEndTestMsg(testName):
    if len(testName) > TEST_MSG_LEN - TEST_MSG_BUFFER:
        raise CustomError("Test name too long.")
    startMsg = ' STARTING '
    endMsg = ' ENDING '
    s1 = (TEST_MSG_LEN - len(testName) - len(startMsg)) // 2
    s2 = (TEST_MSG_LEN - len(testName) - len(endMsg)) // 2
    buf1 = '-' * s1
    buf2 = '-' * s2
    return buf1 + startMsg + testName + ' ' + buf1, buf2 + endMsg + testName + ' ' + buf2 + '\n\n', 

def setupBasic():
    nodes = ['a', 'b', 'c', 'd', 'e']
    d = {}
    d[nodes[0]] = [(nodes[1], 1), (nodes[2], 3)]
    d[nodes[1]] = [(nodes[2], 1), (nodes[3], 3)]
    d[nodes[2]] = [(nodes[3], 1)]
    d[nodes[3]] = [(nodes[4], 1)]
    return nodes, d

def generateConnectedRandomGraph(n, maxW=10, connectivity=0.3, seed=None):
    nodes = ["node" + str(i) for i in range(n)]
    d = defaultdict(list)

    if seed != None: random.seed(seed)

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

    if seed != None: random.seed()
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
    dropper = net.getNode(nodeName).reportHop(testPacket)
    net.removeNode(p1)
    net.removeNode(p2)
    return dropper == None

def identifyDropperBasic(net: Network, packet: Packet, stopTime: int = 100) -> str:
    cur = packet.src
    while cur != None:
        ok = testRouter(net, cur, stopTime)
        cur = net.getNode(cur)
        if not ok: return cur
        cur = cur.reportHop(packet)
    # print("This statement should not have been reached!")
    return None

def sendTestPacket(net: Network, srcNode: Router = None, dstNode: Router = None, 
                   tickCount: int = 200, waitDropperTick: int = 100):
    keepSrcNode = srcNode != None
    keepDstNode = dstNode != None
    res = None
    testPacket = None
    while (res == None):
        srcNode = srcNode if keepSrcNode else net.getRandomNode(False)
        dstNode = dstNode if keepDstNode else net.getRandomNode(False, invalid=set([srcNode]))
        testPacket = Packet(srcNode.getName(), dstNode.getName(), logBit=False, retransmit=False)
        net.send(testPacket)
        net.updateTickN(tickCount)
        # testPacket.printSummary()
        if (testPacket.getStatus() == DROP):
            res = identifyDropperBasic(net, testPacket, waitDropperTick)
    if testPacket != None: testPacket.printSummary()
    return res

def sendTestPacketSupervised(gene, net: Network, srcNode: Router, dstNode: Router):
    ok = True
    res = None
    testPacket = None
    while ok:
        res = next(gene, None)
        if res == None: break     
        testPacket = Packet(srcNode.getName(), dstNode.getName(), logBit=True, retransmit=False)
        net.send(testPacket)
        net.updateTickN(15)
        # testPacket.printSummary()
        ok = testPacket.getStatus() == RECV
    if testPacket != None: testPacket.printSummary()
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

def basic_test1(): #basic: should complete round trip
    startMsg, endMsg = startEndTestMsg("Basic Test 1: Simple Network")
    print(startMsg)

    nodes, d = setupBasic()
    net = Network(40)
    net.changeTopology_nnal(nodes, d)
    testPacket = Packet("a", "e", True)
    net.send(testPacket)
    net.updateTickN(100)
    testPacket.printSummary()
    print(endMsg)

def basic_test2(): #basic: should drop
    startMsg, endMsg = startEndTestMsg("Basic Test 2: Simple Network with Bad Link")
    print(startMsg)

    nodes, d = setupBasic()
    net = Network(40)
    net.changeTopology_nnal(nodes, d)
    ip1 = net.getNodeIP('d')
    ip2 = net.getNodeIP('e')
    net.setLinkWeight((ip1, ip2), np.inf)
    testPacket = Packet("a", "e", True)
    net.send(testPacket)
    net.updateTickN(100)
    testPacket.printSummary()

    print(endMsg)

def basic_test3(): #should report drop (unknown reasons)
    startMsg, endMsg = startEndTestMsg("Basic Test 3: Attacker Present - Drop")
    print(startMsg)

    nodes, d = setupBasic()
    net = Network(40)
    net.changeTopology_nnal(nodes, d)
    maliciousNode = Attacker('d')
    net.setNode(maliciousNode)
    testPacket = Packet("a", "e", True)
    net.send(testPacket)
    net.updateTickN(100)
    testPacket.printSummary()

    print(endMsg)

def probe_test1(): #proof of concept probing
    startMsg, endMsg = startEndTestMsg("Probing Test 1: Proof of Concept")
    print(startMsg)
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
    print(endMsg)

def probe_test2(): #randomized probing in dense networks
    startMsg, endMsg = startEndTestMsg("Probing Test 2: Randomized Probing in Dense Networks")
    print(startMsg)
    nodes, d = generateConnectedRandomGraph(101, 10, 0.8)
    net = Network(50)
    net.changeTopology_nnal(nodes, d)
    maliciousNode = Attacker('node-mal', 5)
    net.addNode(maliciousNode)
    net.triggerNodesExplore()
    print("\nDropper identified to be:", sendTestPacket(net))
    print(endMsg)

def probe_test3(): #supervisory node
    startMsg, endMsg = startEndTestMsg("Probing Test 3: Probing With a Supervisory Node")
    print(startMsg)
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
    print(endMsg)

def random_path_test1():
    startMsg, endMsg = startEndTestMsg("Random Path Test 1: Proof of Concept")
    print(startMsg)
    nodes, d = generateConnectedRandomGraph(n=10, maxW=2, 
                                            connectivity=0.1, 
                                            seed = 69)
    net = Network(RTO = 200)
    net.routingDefault = ProbabilisticDijkstra
    net.dropRandoms = False
    net.changeTopology_nnal(nodes, d)
    r1 = Router("r1")
    net.addNode(r1)
    net.addLink(Link(r1.getIP(), net.getRandomNode().getIP(), weight = 5))
    net.addLink(Link(r1.getIP(), net.getRandomNode().getIP(), weight = 5))
    net.addLink(Link(r1.getIP(), net.getRandomNode().getIP(), weight = 5))
    net.triggerNodesExplore()
    pack = Packet(r1.getName(), net.getRandomNode().getName(), logBit=True)
    net.send(pack)
    net.updateTickTill(pack, RECV, stopTime=300)
    pack.printLogRec()
    print(endMsg)

# basic_test1()
# basic_test2()
# basic_test3()

# probe_test1()
# probe_test2()
# probe_test3()

random_path_test1()

