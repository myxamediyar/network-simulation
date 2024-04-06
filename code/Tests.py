from NetworkObjects import *

nodes = ['a', 'b', 'c', 'd']

d = {}
d[nodes[0]] = [(nodes[1], 1), (nodes[2], 3)]
d[nodes[1]] = [(nodes[2], 1), (nodes[3], 3)]
d[nodes[2]] = [(nodes[3], 1)]

net = Network(100)
net.changeTopology_nnal(nodes, d)
net.printAll()
net.getNode("a").printNextHops()


