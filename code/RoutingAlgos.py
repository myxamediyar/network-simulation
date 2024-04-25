from collections import defaultdict
import heapq
import random
import numpy as np

def Dijkstra(network, startRouter):
    dist = {router: float('infinity') for router in network.getNodes()}
    prevNodes = {router: None for router in network.getNodes()}
    dist[startRouter] = 0

    pQ = [(0, startRouter)]

    while pQ:
        curDist, curRouter = heapq.heappop(pQ)
        
        for link in curRouter.getLinks():
            u, v = link.getEndpoints()
            neighbor = v if curRouter == u else u
            weight = link.weight
            distThruCur = curDist + weight
            if distThruCur < dist[neighbor]:
                dist[neighbor] = distThruCur
                prevNodes[neighbor] = curRouter
                heapq.heappush(pQ, (distThruCur, neighbor))
    return dist, prevNodes


def DijkstraNextHopDist(network, startRouter):
    dist, prevNodes = Dijkstra(network, startRouter)
    nextHopVector = defaultdict(lambda _: None)
    for dst in prevNodes:
        curNode = dst
        prev = dst
        while curNode != startRouter: 
            prev = curNode
            if prev == None:
                break
            curNode = prevNodes[curNode]
        nextHopVector[dst] = prev
    d = {}
    for to, hop in nextHopVector.items():
        d[to.getName()] = None if hop == None else hop.getName()
    return d, dist

def DijkstraNextHop(network, startRouter):
    return DijkstraNextHopDist(network, startRouter)[0]

def ProbabilisticDijkstra(network, startRouter):
    # startRouter.setAuxiliary(DijkstraNextHop, network, startRouter)
    res, dist = DijkstraNextHopDist(network, startRouter)
    def select_random_node(vec):
        nodes = list(vec.values())
        weights = np.array([1 / dist[network.getNode(node)] if node != startRouter.getName() else 0 for node in nodes])
        weights /= np.sum(weights)
        if not nodes: return None
        chosenNode = random.choices(nodes, weights=weights, k=1)[0]
        return chosenNode

    startRouter.setHopWrapper(lambda vec, _: select_random_node(vec))
    return res