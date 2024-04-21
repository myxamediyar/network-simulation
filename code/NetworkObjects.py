# Definitions of network objects here

#region imports
from collections import defaultdict
from enum import Enum
import random
from copy import deepcopy
from RoutingAlgos import *

#Packet status
class Status(Enum):
    FRESH = 0
    SENT = 1
    RECV = 2
    ACK = 3
    INVALID_MAPPING = 4
    DROP = 5

LARGE_PRIME = 112272535095293
def generateRandomID():
    return (random.randint(1, 2**32 - 1)) % LARGE_PRIME

FRESH = Status.FRESH
SENT = Status.SENT
ACK = Status.ACK
RECV = Status.RECV
INVALID_MAPPING = Status.INVALID_MAPPING
DROP = Status.DROP

#Custom error
class CustomError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message

#class defs
class Router: pass
class Link: pass
class Packet: pass
class Network: pass
class Attacker(Router): pass
class Defender(Router): pass
#endregion

# router object
class Router:
    def __init__(self, name: str = None):
        self.__destroyed = False
        self.__nextHopVector = defaultdict(lambda: None)
        self.__ackAwaitBuffer = set()
        self.__dropHop = defaultdict(lambda: None)
        self.__completed = set()
        self.__links = set()
        self.configure(name, ip = generateRandomID())
        self.setRoutingAlgorithm(lambda x: None)

    def configure(self, name: str = None, ip: int = -1, network: Network = None, packets: list[Packet] = set()):
        """Sets or updates the configuration for the router."""
        self.__name = name
        self.__ip = ip
        self.__network = network
        self.__packets = packets
    
    def forwardAll(self):
        for p in self.__packets:
            self.__process(p)
            if p.getStatus() == DROP: #discard if dropped
                continue
            if p.getStatus() == RECV: #round trip complete
                continue
            nextHopName = self.__nextHopVector[p.dst]
            if nextHopName == None:
                if self.getNetwork().tryDNS(nextHopName):
                    self.updateRoutingTable()
                nextHopName = self.__nextHopVector[p.dst]
                if nextHopName == None:
                    self.drop(p)
                    continue
            nextHopIP = self.__network.getIP(nextHopName)
            nextLink = self.__network.getLink((self.getIP(), nextHopIP))
            nextLink.addPacket(p)
        self.__packets = set()

    def __process_basic(self, packet):
        ## mark and log
        msg = f"At {self}."
        packet.incrTimeStamp()
        packet.intermedIP = self.getIP()
        if packet.getStatus() == FRESH:
            packet.incrTimeSent()
            self.__ackAwaitBuffer.add(packet)
            packet.log(self, f"Packet added to {self}")
            packet.setStatus(SENT)
            msg = f"Packet sent."
        elif packet.getStatus() == ACK:
            if packet not in self.__ackAwaitBuffer:
                print("WARNING: A non waited upon ACK'd packet received and discarded!")
                msg = f"Dropped random ACK'd packet."
                packet.setStatus(DROP)
            else:
                self.__completed.add(packet)
                self.__ackAwaitBuffer.remove(packet)
                packet.setStatus(RECV)
                msg = f"Round trip completed."
        elif packet.dst == self.getName():
            packet.setStatus(ACK)
            msg = "Packet received."
            packet.dst, packet.src = packet.src, packet.dst
        else:
            self.__ackAwaitBuffer.add(packet)
        packet.log(self, msg)

    def checkAck(self):
        droppedPackets = set()
        t = self.__network.getTime()
        rto = self.__network.RTO
        for p in self.__ackAwaitBuffer:
            if t - p.getTimeSent() > rto:
                droppedPackets.add(p)
                _, v = p.src, p.dst
                if p.getStatus() == ACK:
                    _, v = v, _
                self.recordDropHop(p, self.__nextHopVector[v])
                self.drop(p)
                self.retransmit(p, p.retransmit)
        self.__ackAwaitBuffer -= droppedPackets

    def drop(self, p: Packet):
        p.setStatus(DROP)
        p.log(self, f"Packet dropped by {self}.")
        p.incrTimeStamp()

    def retransmit(self, p, addNow: bool = True):
        p1 = deepcopy(p)
        p.retransmitNext = p1
        p1.refresh(self)
        if addNow:
            self.addPacket(p1)
        return p1
    
    def recordDropHop(self, packet: Packet, nextHop: str):
        self.__dropHop[packet] = nextHop

    def reportDropHop(self, packet):
        return self.__dropHop[packet]

    def __process(self, packet: Packet):
        ##malicious will be able to modify this
        ##method to proces the packets differently
        self.__process_basic(packet)

    def updateRoutingTable(self):
        ##fetch topology
        ##run routing algorithm
        ##for every node, determine next hop
        self.__nextHopVector = self.__routing(self.__network, self)
    
    def setRoutingAlgorithm(self, algorihtm):
        self.__routing = algorihtm

###---------FOR ALL GETTERs PERFORM DEEP COPY---------####

    #region router Name
    def getName(self):
        return self.__name

    def setName(self, name: str):
        #check uniqueness
        self.configure(name=name, ip=self.__ip, network=self.__network, packets=self.__packets)
    #endregion
    #region router IP
    def getIP(self):
        return self.__ip

    def setIP(self, ip: int):
        self.configure(name=self.__name, ip=ip, network=self.__network, packets=self.__packets)
    #endregion
    #region router Network
    def getNetwork(self):
        return self.__network

    def setNetwork(self, network: Network):
        self.configure(name=self.__name, ip=self.__ip, network=network, packets=self.__packets)
    #endregion
    #region router Links
    def getLinks(self):
        return [self.getNetwork().getLink(id) for id in self.__links]

    def addLink(self, linkID: int):
        self.__links.add(linkID)

    def removeLink(self, linkID: int):
        self.__links.remove(linkID)
    #endregion   
    #region router Packets
    def getPackets(self):
        return self.__packets.copy()

    def setPackets(self, packets: list[Packet]):
        self.configure(name=self.__name, ip=self.__ip, network=self.__network, packets=packets)

    def addPackets(self, packets: list[Packet]):
        self.__packets = self.__packets.union(set(packets))

    def addPacket(self, packet):
        self.addPackets([packet])

    def printNextHops(self):
        for k, v in self.__nextHopVector.items():
            print("To", k, "through", v)

    #endregion
    

    def preprocess(self):
        pass


    # Additional method to check if the router is destroyed
    def isDestroyed(self):
        return self.__destroyed

    def destroy(self):
        """Destroys the router and cleans up its resources."""
        self.configure(name="Null", ip=-1, network=None, packets=[])
        self.__destroyed = True

    def __repr__(self):
        return f"Router({self.__name})"
    
    def __lt__(self, other):
        if not isinstance(other, Router):
            return NotImplemented
        return self.getName() < other.getName()

    def __gt__(self, other):
        if not isinstance(other, Router):
            return NotImplemented
        return self.getName() > other.getName()
    
    def __le__(self, other):
        if not isinstance(other, Router):
            return NotImplemented
        return self.getName() <= other.getName()

    def __ge__(self, other):
        if not isinstance(other, Router):
            return NotImplemented
        return self.getName() >= other.getName()

# Link object
class Link:
    def __init__(self, u: int, v: int, weight: float = 1, network: Network = None):
        self.weight = weight
        self.u = u
        self.v = v
        self.id = generateRandomID()
        self.__packets = set()
        self.__network = network

    def addPacket(self, packet: Packet):
        if self.__network == None:
            raise CustomError("Link is not attached to a network!")
        if packet in self.__packets:
            raise CustomError("Packet already on Link!")
        packet.incrTimeStamp()
        self.__packets.add(packet)
    
    def getEndpoints(self) -> tuple[Router, Router]:
        return (self.__network.getNodeIP(self.u), self.__network.getNodeIP(self.v))
    
    def hasEndpoint(self, ip: int) -> bool:
        return ip == self.u or ip == self.v


    def deliverPackets(self):
        discarded = set()
        for p in self.__packets:
            if p.getStatus() == DROP:
                p.log(self, f"Packet dropped by source, stopped logging at {self}")
                discarded.add(p)
                continue
            p.log(self, f"At link {self}")
            u, v = self.getEndpoints()
            if self.__network.getTime() - p.getTimeStamp() > self.weight:
                # print("PACKET", self.__network.getTime(), p.getTimeStamp(), self.weight)
                discarded.add(p)
                if p.intermedIP == self.u:
                    v.addPacket(p)
                else:
                    u.addPacket(p)
        self.__packets -= discarded

    def setNetwork(self, network: Network):
        self.__network = network

    def getNetwork(self):
        return self.__network

    def __repr__(self):
        u, v = self.getEndpoints()
        return f"Link({u.getName()} <-> {v.getName()})"

# Network topology
class Network:
    def __init__(self, RTO: int = 20):
        self.__time = 0
        self.__dns = {}
        self.__links = {}
        self.__nodes = {}
        self.RTO = RTO
        self.numNodes = 0
    
    def updateTick(self):
        ###increment time
        self.incrementTime()
        ###peform all deliveries to routers
        links = set(self.__links.values())
        nodes = set(self.__nodes.values())
        for l in links:
            l.deliverPackets()
        for n in nodes:
            ###peform ack TTL checks
            ###make routers forward packets (based on time)
            ###check if any packet is destined to you
            n.checkAck()
            n.forwardAll()
            
    def updateTickN(self, n: int):
        for _ in range(n):
            self.updateTick()

    def updateTickTill(self, packet: Packet, status: Status, stopTime: int = 100):
        while packet.getStatus() != status and stopTime:
            self.updateTick()
            stopTime -= 1
    
    def printAll(self):
        print("Nodes:")
        for n in self.__nodes.values():
            print(n)
        print("Links:")
        links = set(self.__links.values())
        for l in links:
            print(l)
        

    def changeTopology_l(self, links: list[Link], routers: list[Router]):
        """Update all links and invalidate inactive nodes"""
        
        old_nodes = set()
        for e in self.__links:
            old_nodes.add(e.u)
            old_nodes.add(e.v)
        new_nodes = set()
        for e in links:
            new_nodes.add(e.u)
            new_nodes.add(e.v)

        obsolete_nodes = old_nodes - new_nodes
        for n in obsolete_nodes:
            node = self.getNodeIP(n)
            node.destroy()
        self.__setNodeMap(routers)
        self.__setLinkMap(links)
        self.refreshDns()
        self.triggerNodesExplore()

    def changeTopology_rw(self, edges: list[(Router, Router)], weights: list[int]):
        if len(edges) != len(weights):
            raise CustomError("Number of edges != Number of weights")
        links = []
        routers = set()
        for i in range(len(edges)):
            u, v, w  = edges[i][0], edges[i][1], weights[i]
            links.append(Link(u, v, w, self))
            routers.add(u)
            routers.add(v)
        self.changeTopology_l(links, list(routers))

    def changeTopology_nnal(self, node_names, adjacency_list):
        ###     0 3 1      a
        ###     3 0 2      b
        ###     1 0 0      c
        adjacency_list = defaultdict(list, adjacency_list)
        links = []
        routers = set()
        namesUsed = {}
        for n in node_names:
            if n in namesUsed:
                r1 = namesUsed[n]
            else:
                r1 = Router(n)
                namesUsed[n] = r1
            for v, w in adjacency_list[n]:
                if v in namesUsed:
                    r2 = namesUsed[v]
                else:
                    r2 = Router(v)
                    namesUsed[v] = r2
                links.append(Link(r1.getIP(), r2.getIP(), w, self))
                routers.add(r1)
                routers.add(r2)
        self.changeTopology_l(links, routers)


    def refreshDns(self):
        for e in self.__links.values():
            u, v = e.getEndpoints()
            self.__dns[u.getName()] = u.getIP()
            self.__dns[v.getName()] = v.getIP()

    def triggerNodesExplore(self):
        nodes = set(self.__nodes.values())
        for n in nodes:
            r: Router = n
            r.updateRoutingTable()

    def __setLinkMap(self, links: list[Link]):
        self.__links.clear()
        for e in links:
            self.addLink(e)

    def __setNodeMap(self, nodes: list[Router]):
        self.__nodes.clear()
        for n in nodes:
            self.addNode(n)

    def addNode(self, router: Router, skipChecks: bool = False):
        if not skipChecks:
            if router.getIP() in self.__nodes:
                raise CustomError("Router with given IP or Name already exists!")
            if router.getName() in self.__dns:
                print("WARNING: name already exists!")
                return
        self.numNodes += 1
        router.setNetwork(self)
        router.setRoutingAlgorithm(DijkstraNextHop)
        self.__nodes[router.getIP()] = router
        self.__dns[router.getName()] = router.getIP()
        router.preprocess()

    def removeNode(self, router: Router):
        ip = router.getIP()
        name = router.getName()
        self.numNodes -= 1
        linksRemove = []
        for link in router.getLinks():
            u, v = link.getEndpoints()
            u.removeLink(link.id)
            v.removeLink(link.id)
            linksRemove.extend([link.id, (link.u, link.v), (link.v, link.u)])


        for key in linksRemove:
            del self.__links[key]

        if ip in self.__nodes:
            del self.__nodes[ip]
        else:
            raise CustomError("Router with the given IP does not exist!")

        if name in self.__dns:
            del self.__dns[name]
        else:
            print("WARNING: Router name not found in DNS.")

    
    def addLink(self, link: Link, ignoreId: bool = False):
        if not ignoreId and link.id in self.__links:
            raise CustomError("Link already exists")
        link.setNetwork(self)
        u, v = link.getEndpoints()
        ip1, ip2 = link.u, link.v
        if (ip1, ip2) in self.__links:
            return
        self.__links[(ip1, ip2)] = link
        self.__links[(ip2, ip1)] = link
        self.__links[link.id] = link
        u.addLink(link.id)
        v.addLink(link.id)

    def setLink(self, link: Link):
        self.addLink(link)
        self.triggerNodesExplore()
        
        
    def changeDNSEntry(self, oldname: str, newname: str) -> bool:
        if newname in self.__dns:
            raise CustomError("Couldn't change DNS entry - New Name already exists")
        n = self.__dns[oldname]
        self.__dns[newname] = n
        del self.__dns[oldname]
        return True
    
    def getDNSIP(self, name):
        if name not in self.__dns:
            raise CustomError("Couldn't find DNS entry - name doesn't exist")
        return self.__dns[name]
    
    def tryDNS(self, name):
        return name in self.__dns

    def incrementTime(self):
        self.__time += 1

    def scheduleSend(self, name: str):
        ... #maybe
    
    def send(self, packet: Packet):
        srcNode = self.getNode(packet.src)
        if srcNode == None:
            raise CustomError("Src for packet wasn't found!")
        packet.setNetwork(self)
        packet.setStatus(FRESH)
        srcNode.addPacket(packet)
        
    
    def getTime(self) -> int:
        return self.__time
    
    def getNodes(self) -> list[Router]:
        return list(self.__nodes.values())
    
    def getNode(self, name: str) -> Router:
        ip = self.__dns[name]
        if ip == None:
            return None
        return self.__nodes[ip]

    def getRandomNode(self, targetAll: bool = True, failureCond: int = 100):
        failureCond = 1 if targetAll else failureCond
        keys = list(self.__nodes.keys())
        while (failureCond):
            randInd = random.randint(0, len(keys) - 1)
            res = self.__nodes[keys[randInd]]
            typeCheck = type(res) == Attacker or type(res) == Defender
            if targetAll or typeCheck: return res
            failureCond -= 1
        raise CustomError("No valid node found!")
    

    
    def getNodeIP(self, ip) -> Router:
        return self.__nodes[ip]
        
    
    def setNode(self, node: Router):
        """
        Use if you want to replace a node.
        """
        name = node.getName()
        prevNode = self.getNode(name)
        if prevNode != None:
            node.setIP(prevNode.getIP())
        self.addNode(node, True)
        node.updateRoutingTable()
        

    
    def getLink(self, id_or_ipTuple) -> Link:
        return self.__links[id_or_ipTuple]
    
    def setLinkWeight(self, id_or_ipTuple, w):
        self.__links[id_or_ipTuple].weight = w

    
    def getIP(self, name: str) -> int:
        node = self.getNode(name)
        if node == None:
            raise CustomError("Name to IP mapping doesn't exit")
        return node.getIP()

# Packet object
class Packet:

    def __init__(self, src: str, dst: str, logBit: bool = False, status: Status = None, network: Network = None, retransmit = True):
        self.src = src
        self.dst = dst
        self.intermedIP = -1
        self.__logBit = logBit
        self.__log = []
        self.__summary = [None, [], None]
        self.retransmitNext = None
        self.retransmit = retransmit
        self.__timeSent = -1000000
        self.__timeStamp = -1000000
        self.rtCount = 0
        self.packetID = generateRandomID()
        self.configure(status, network)
        
    def configure(self, status: Status = None, network: Network = None):
        """Defaults to Null values for all fields, so use set methods when changing only one field."""
        self.status = status
        self.__network = network

    def networkCheck(self):
        if self.__network == None:
            raise CustomError("Packet is not on a network!")

    def refresh(self, router):
        self.__timeSent = -1000000
        self.__timeStamp = -1000000

        self.configure(FRESH, router.getNetwork())

    def setStatus(self, status: Status):
        self.configure(status, self.__network)

    def getStatus(self) -> Status:
        return self.status

    def getStatusStr(self):
        return str(self.status)[7:]
    
    def incrTimeStamp(self):
        self.networkCheck()
        self.__timeStamp = self.__network.getTime()
    
    def getTimeStamp(self):
        self.networkCheck()
        return self.__timeStamp
    
    def incrTimeSent(self):
        self.networkCheck()
        self.__timeSent = self.__network.getTime()
    
    def getTimeSent(self):
        self.networkCheck()
        return self.__timeSent

    def incrRTcount(self):
        self.rtCount += 1

    def setNetwork(self, network: Network):
        # perform checks and call necessary method in network object (delete + append shit)
        self.configure(self.status, network)


    def __repr__(self):
        return f"Packet(SRC: {self.src}; DST: {self.dst}; STATUS: {self.getStatusStr()})"
    
    ###ADD LOGS METHODS
    def log(self, who, msg):
        if type(who) == Router and self.getStatus() not in [DROP, FRESH]:
            self.__summary[1].append(who.getName())
        logInfo = f"TIMESTAMP {self.__network.getTime()}: {self} is at {who}.\n{' ' * (len(' TIMESTAMP ') + len(str(self.__network.getTime())))}Message: {msg}"
        if self.__logBit:
            self.__log.append(logInfo)
        if self.getStatus() == FRESH:
            self.__summary[0] = msg
        if self.getStatus() == DROP or self.getStatus() == RECV:
            self.__summary[2] = msg
            
    def printLog(self):
        for m in self.__log:
            print(m)
    
    def printLogRec(self):
        n = self
        i = 0
        while (n != None) and (i < 10):
            n.printLog()
            n = n.retransmitNext
            i += 1

    def printSummary(self):
        print(f"{self} summary:")
        print("-", self.__summary[0])
        travelPath = ','.join(self.__summary[1])
        print("-", "Visisted nodes: " + travelPath)
        print("-", self.__summary[2])
        print("-", "Time sent:", self.getTimeSent(), "\n- Last logged time:", self.getTimeStamp())



class Attacker(Router): 
    def __init__(self, name: str, attackNum: int, targetAll: bool = True, failureCond: int = 100):
        super().__init__(name)
        self.attackNum = attackNum
        self.targetAll = targetAll
        self.failureCond = failureCond

    def updateRoutingTable(self):
        self.__nextHopVector = defaultdict(lambda: None)
    
    def setRoutingAlgorithm(self, algorihtm):
        return

    def preprocess(self):
        net: Network = self.getNetwork()
        for _ in range(self.attackNum):
            victim = net.getRandomNode(self.targetAll, self.failureCond)
            net.addLink(
                Link(self.getIP(), victim.getIP(), 0)
            )
            

    def reportDropHop(self, _):
        links = self.getLinks()
        if not len(links):
            raise CustomError("Isolated node detected!")
        random.shuffle(links)
        return links[0]

                
class Defender(Router):
    def __init__(self, name: str):
        super().__init__(name)

    def preprocess(self):
        net: Network = self.getNetwork()
        for n in net.getNodes():
            net.addLink(Link(self.getIP(), n.getIP(), 0))
    

