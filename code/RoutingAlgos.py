from collections import defaultdict
import heapq

def Dijkstra(network, startRouter):
    dist = {router: float('infinity') for router in network.getNodes()}
    prevNodes = {router: None for router in network.getNodes()}
    dist[startRouter] = 0

    pQ = [(0, startRouter)]

    while pQ:
        curDist, curRouter = heapq.heappop(pQ)
        
        for link in curRouter.getLinks():
            neighbor = link.v if curRouter == link.u else link.u
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

