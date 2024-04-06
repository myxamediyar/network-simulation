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


##TODO: fix, this is WRONG
def DijkstraNextHop(network, startRouter):
    _, prevNodes = Dijkstra(network, startRouter)
    nextHopVector = {}

    for destination, prevNode in prevNodes.items():
        currentNode = destination

        if currentNode == startRouter:
            nextHopVector[currentNode] = None
            continue

        while prevNode is not None and prevNodes[prevNode] != startRouter:
            currentNode = prevNode
            prevNode = prevNodes[prevNode]
        
        nextHopVector[destination] = currentNode

    return nextHopVector
