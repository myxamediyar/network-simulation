import objects as o

nodes = ['a', 'b', 'c', 'd']

d = {}
d[nodes[0]] = [(nodes[1], 3), (nodes[2], 3)]
d[nodes[1]] = [(nodes[3], 1), (nodes[0], 2)]
d[nodes[3]] = [(nodes[2], 5), (nodes[1], 1)]

net = o.Network(100)
net.changeTopology_nnal(nodes, d)
net.printAll()