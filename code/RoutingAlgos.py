from collections import defaultdict
import heapq
import random
from tracemalloc import start

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


def DijkstraNextHop(network, startRouter):
    _, prevNodes = Dijkstra(network, startRouter)
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
    return d

def ProbabilisticDijkstra(network, startRouter):
    # startRouter.setAuxiliary(DijkstraNextHop, network, startRouter)
    startRouter.setHopWrapper(lambda vec, name: vec[random.choice(list(vec.keys()))])
    res = DijkstraNextHop(network, startRouter)
    print(res)
    return res