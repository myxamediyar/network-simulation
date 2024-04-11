from NetworkObjects import *
from RoutingAlgos import *
import numpy as np


def test1():
    nodes = ['a', 'b', 'c', 'd', 'e']

    d = {}
    d[nodes[0]] = [(nodes[1], 1), (nodes[2], 3)]
    d[nodes[1]] = [(nodes[2], 1), (nodes[3], 3)]
    d[nodes[2]] = [(nodes[3], 1)]
    d[nodes[3]] = [(nodes[4], 1)]

    net = Network(10)
    net.changeTopology_nnal(nodes, d)
    ip1 = net.getIP('d')
    ip2 = net.getIP('e')
    net.setLinkWeight((ip1, ip2), np.inf)
    testPacket = Packet("a", "e", True)
    net.send(testPacket)
    net.updateTickN(100)
    # testPacket.printLogRec()


#TODO: malciiosu
#TODO: fix drop - not dropping

test1()

