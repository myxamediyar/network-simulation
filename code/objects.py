# Definitions of network objects here

#region imports
from ast import List
from collections import defaultdict
from enum import Enum

#Packet status
class Status(Enum):
    FRESH = 0
    SENT = 1
    RECV = 2
    ACK = 3
    RET = 4
    DROP = 5

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
        self.__nextHop = {}
        self.configure(name)

    def configure(self, name: str = None, ip: int = -1, network: Network = None, links: List[Link] = [], packets: List[Packet] = [], ackAwaitBuffer: List[Packet] = []):
        """Sets or updates the configuration for the router."""
        self.__name = name
        self.__ip = ip
        self.__network = network
        # self.__links = links
        self.__packets = packets
        self.__ackAwaitBuffer = ackAwaitBuffer
    
    def forward(self):
        for p in self.__packets:
            nextHopName = self.__nextHop[p.name]
            ipHop = self.__network.dns[nextHopName]
            nextLink = self.__network.links[(self.getIp(), ipHop)]
            self.__process(p)
            nextLink.putOnLink(p)

    def __process(self, packet):
        ## mark and log
        ...

    
    def updateRoutingTable(self, algorithm):
        ##fetch topology
        ##run routing algorithm
        ##for every node, determine next hop
        self.__nextHop = algorithm(self.__network)

###---------FOR ALL SETTERS PERFORM DEEP COPY---------####

    #region router Name
    def getName(self):
        return self.__name

    def setName(self, name: str):
        #check uniqueness
        self.configure(name=name, ip=self.__ip, network=self.__network, links=self.__links, packets=self.__packets)
    #endregion
    #region router IP
    def getIp(self):
        return self.__ip

    def __setIp(self, ip: int):
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
        self.configure(name=self.__name, ip=self.__ip, network=self.__network, links=links, packets=self.__packets)
    #endregion   
    #region router Packets
    def getPackets(self):
        return self.__packets

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
    def __init__(self, u: Router, v: Router, id: int, weight: float = 1):
        self.weight = weight
        self.u = u
        self.v = v
        self.id = id
        self.packets = []

    def putPacket(self, packet: Packet):
        self.packets.append(packet)
        
    def __repr__(self):
        return f"Link({self.u.name} <-> {self.v.name})"

# Network topology
class Network:
    def __init__(self):
        self.__linkcount = 0
        self.__ipcount = 0
        self.__time = 0
        self.__dns = None
        self.__links = {}
        self.__nodes = {}
        return
    
    def updateTick(self):
        ###increment time
        ###peform all deliveries to routers
        ###peform ack TTL checks
        ###check if any packet is destined to you
        ###make routers forward packets (based on time)
        ...

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
        self.__nodes = list(new_nodes)
        self.__setLinkMap(links)
        self.refreshDns()
        self.__nodesExplore()

    def refreshDns(self):
        for e in self.__links:
            self.__dns[e.u.name] = e.u
            self.__dns[e.v.name] = e.v
    
    def __setLinkMap(self, links: List[Link]):
        self.__links.clear()
        for e in links:
            self.__links

    
    def updateDNSEntry(self, oldname: str, newname: str) -> bool:
        if newname in self.__dns:
            print("Couldn't update DNS entry - New Name already exists")
            return False
        n = self.__dns[oldname]
        self.__dns[newname] = n
        del self.__dns[oldname]
        return True


    def incrementTime(self):
        self.__time += 1

    def scheduleSend(self, name: str):
        ... #maybe 
    
    def reportTick(self) -> int:
        return self.__time
        

# Packet object
class Packet:
    def __init__(self, src: str, dst: str, logBit: bool = False, status: Status = None, network: Network = None):
        self.src = src
        self.dst = dst
        self.__logBit = logBit
        self.__log = []
        self.configure(status, network)
        
    def configure(self, status: Status = None, network: Network = None):
        """Defaults to Null values for all fields, so use set methods when changing only one field."""
        self.status = status
        self.__network = network

    def init(self, router):
        self.configure(FRESH, router.getNetwork())

    def __setLink(self, link: Link):
        self.configure(self.status, self.__network)

    def setStatus(self, status: Status):
        self.configure(self.__link, status, self.__network)

    def getStatusStr(self):
        return str(self.status)[7:]

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

# Packet