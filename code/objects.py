# Definitions of network objects here

#region imports
from ast import List
from collections import defaultdict
from enum import Enum
from random import random
from copy import deepcopy

#Packet status
class Status(Enum):
    FRESH = 0
    SENT = 1
    RECV = 2
    ACK = 3
    RET = 4
    DROP = 5

LARGE_PRIME = 112272535095293
def generateRandomID():
    return (random.randint(1, 2**32 - 1)) % LARGE_PRIME

FRESH = Status.FRESH
SENT = Status.SENT
RECV = Status.RECV
ACK = Status.ACK
RET = Status.RET
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
        self.__nextHopVector = {}
        self.__ackAwaitBuffer = set()
        self.__completed = set()
        self.configure(name)

    def configure(self, name: str = None, ip: int = -1, network: Network = None, packets: List[Packet] = []):
        """Sets or updates the configuration for the router."""
        self.__name = name
        self.__ip = ip
        self.__network = network
        self.__packets = packets
    
    def forwardAll(self):
        for p in self.__packets:
            if p.getStatus() == DROP: #discard if dropped
                continue
            src = p.src
            dst = p.dst
            if p.getStaus() == RECV: 
                src, dst = dst, src
            nextHopName = self.__nextHopVector[p.dst.name]
            ipHop = self.__network.dns[nextHopName]
            nextLink = self.__network.links[(self.getIp(), ipHop)]
            self.__process(p)
            nextLink.addPacket(p)
        self.__packets = set()

    def __process_basic(self, packet):
        ## mark and log
        msg = f"At {self}."
        packet.incrTimeStamp()
        if packet.status == FRESH:
            packet.setStatus(SENT)
            self.__ackAwaitBuffer.add(packet)
            msg = f"Packet sent."
        elif packet.status == RECV and packet in self.__ackAwaitBuffer:
            self.__completed.add(packet)
            self.__ackAwaitBuffer.remove(packet)
            packet.setStatus(ACK)
            msg = f"Round trip completed."
        elif packet.dst == self:
            packet.setStatus(RECV)
            msg = "Packet received."
        packet.log(self, msg)

    def checkAck(self):
        t = self.__network.getTime()
        rto = self.__network.RTO
        for p in self.__ackAwaitBuffer:
            if t - p.getTimeSent() > rto:
                p.setStatus(DROP)
                p = deepcopy(p)
                p.incrRTcount()
                p.refresh(self)
                self.addPacket(p)
        
                

    def __process(self, packet: Packet):
        ##malicious will be able to modify this
        ##method to proces the packets differently
        self.__process_basic(packet)

    def updateRoutingTable(self):
        ##fetch topology
        ##run routing algorithm
        ##for every node, determine next hop
        self.__nextHopVector = self.__routing(self.__network)
    
    def setRoutingAlgorithm(self, algorihtm):
        self.__routing = algorihtm

###---------FOR ALL SETTERS PERFORM DEEP COPY---------####

    #region router Name
    def getName(self):
        return self.__name

    def setName(self, name: str):
        #check uniqueness
        self.configure(name=name, ip=self.__ip, network=self.__network, links=self.__links, packets=self.__packets)
    #endregion
    #region router IP
    def getIP(self):
        return self.__ip

    def __setIP(self, ip: int):
        self.configure(name=self.__name, ip=ip, network=self.__network, links=self.__links, packets=self.__packets)
    #endregion
    #region router Network
    def getNetwork(self):
        return self.__network

    def __setNetwork(self, network: Network):
        self.configure(name=self.__name, ip=self.__ip, network=network, links=self.__links, packets=self.__packets)
    #endregion
    #region router Links
    def getLinks(self):
        return self.__links

    def __setLinks(self, links: List[Link]):
        self.configure(name=self.__name, ip=self.__ip, network=self.__network, packets=self.__packets)
    #endregion   
    #region router Packets
    def getPackets(self):
        return self.__packets.copy()

    def setPackets(self, packets: List[Packet]):
        self.configure(name=self.__name, ip=self.__ip, network=self.__network, links=self.__links, packets=packets)

    def addPackets(self, packet: List[Packet]):
        self.__packets.extend(packet)

    def addPacket(self, packet):
        self.addPackets([packet])

    #endregion
     
    # Additional method to check if the router is destroyed
    def isDestroyed(self):
        return self.__destroyed

    def destroy(self):
        """Destroys the router and cleans up its resources."""
        self.configure(name="Null", ip=-1, network=None, links=[], packets=[])
        self.__destroyed = True

    def __repr__(self):
        return f"Router({self.__name})"


# Link object
class Link:
    def __init__(self, u: Router, v: Router, weight: float = 1, network: Network = None):
        self.weight = weight
        self.u = u
        self.v = v
        self.id = generateRandomID
        self.__packets = set()
        self.__network = network

    def addPacket(self, packet: Packet):
        if self.__network == None:
            raise CustomError("Link is not attached to a network!")
        if packet in self.packets:
            raise CustomError("Packet already on Link!")
        packet.setTimeStamp()
        self.__packets.add(packet)

    def deliverPackets(self):
        discarded = set()
        for p in self.__packets:
            if self.__network.getTime() - p.getTimeStamp() > self.weight:
                discarded.add(p)
                if p.intermed == self.u:
                    self.v.addPacket(p)
                else:
                    self.u.addPacket(p)
                p.log(self, f"At link {self}")
        self.__packets -= discarded


    def __repr__(self):
        return f"Link({self.u.name} <-> {self.v.name})"

# Network topology
class Network:
    def __init__(self, RTO: int = 20):
        self.__time = 0
        self.__dns = None
        self.__links = {}
        self.__nodes = []
        self.RTO = RTO
    
    def updateTick(self):
        ###increment time
        self.__time += 1
        ###peform all deliveries to routers
        links = self.__links.values()
        nodes = self.__nodes.values()
        for l in links:
            l.deliverPackets()
        for n in nodes:
            ###peform ack TTL checks
            ###make routers forward packets (based on time)
            ###check if any packet is destined to you
            n.checkAck()
            n.forward()

    def changeTopology(self, links: List[Link]):
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
            n.destroy()
        self.__setNodeMap(list(new_nodes))
        self.__setLinkMap(links)
        self.refreshDns()
        self.__nodesExplore()

    def refreshDns(self):
        for e in self.__links:
            self.__dns[e.u.name] = e.u
            self.__dns[e.v.name] = e.v
    
    def __nodesExplore(self):
        nodes = set(self.__nodes)
        for n in nodes:
            r: Router = n
            r.updateRoutingTable()

    def __setLinkMap(self, links: List[Link]):
        self.__links.clear()
        for e in links:
            ip1, ip2 = e.u.getIP(), e.v.getIP()
            self.__links[(ip1, ip2)] = e
            self.__links[(ip2, ip1)] = e
            self.__links[e.id] = e

    def __setNodeMap(self, nodes: List[Router]):
        self.__nodes.clear()
        for n in nodes:
            self.__nodes[n.getIP()] = n
            self.__nodes[n.getName()] = n        
    
    def updateDNSEntry(self, oldname: str, newname: str) -> bool:
        if newname in self.__dns:
            raise CustomError("Couldn't update DNS entry - New Name already exists")
        n = self.__dns[oldname]
        self.__dns[newname] = n
        del self.__dns[oldname]
        return True


    def incrementTime(self):
        self.__time += 1

    def scheduleSend(self, name: str):
        ... #maybe 
    
    def getTime(self) -> int:
        return self.__time
        

# Packet object
class Packet:

    def __init__(self, src: str, dst: str, logBit: bool = False, status: Status = None, network: Network = None):
        self.src = src
        self.dst = dst
        self.intermed = src
        self.__logBit = logBit
        self.__log = []
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
        self.configure(FRESH, router.getNetwork())

    def setStatus(self, status: Status):
        self.configure(self.__link, status, self.__network)

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

    def __setNetwork(self, network: Network):
        # perform checks and call necessary method in network object (delete + append shit)
        self.configure(self.__link, self.status, network)


    def __repr__(self):
        return f"Packet(SRC: {self.src}; DST: {self.dst}; STATUS: {self.getStatusStr()})"
    
    ###ADD LOGS METHODS
    def log(self, who, msg):
        if self.__logBit:
            self.__log.append(f"TIMESTAMP {self.__network.__time}: {self} is at {who}. 
                              \n{' ' * (len(' TIMESTAMP ') + len(str(self.__network.__time)))}Message: {msg}.")
    def printLog(self):
        for m in self.__log:
            print(m)
