# -*- coding: utf-8 -*-
"""
Created on Thu Sep 20 14:35:31 2018

@author: V17IAhmed36
"""
import netaddr
from Firewall import Firewall,WriteFile,ReadReadFile

class SRX(Firewall):
    
    def __init__(self,name,ip,username,password,configFile,routeFile):
        Firewall.__init__(self, name,ip,username,password,configFile,routeFile)
        self.type = "SRX"
        self.routeTable = self.getRouteTable()
        
    def getRouteTable(self):
        #Iterates through the Route file and return routeing table
        lineIndex = 0
        routeTable = {}
        while(lineIndex < len(self.routeFile)):
            buff = self.routeFile[lineIndex].split()
            if (len(buff) > 0):
                address = buff[0].split('/')[0] # checks if this lines contains IPv4 subnet
                if(netaddr.valid_ipv4(address) and (not self.routeFile[lineIndex+1].find('via') == -1) and self.routeFile[lineIndex+1] not in ['Discard','Reject']):#check if the IPv4 is valid and if the route is not discarded nor rejected
                    routeTable[netaddr.IPNetwork(buff[0])]=self.routeFile[lineIndex+1].split()[-1]# add the route to route table dictionary
            lineIndex += 1
        return routeTable
    
    def getRouteInterface(self,IP):
        #return the route Interface for a subnet and returns None if no route found even default, IP in netaddr IPv4 Network
        bestMatchInterface = None
        bestMatchSubnet = netaddr.IPNetwork("0.0.0.0/0")
#        bestMatchSize = bestMatchSubnet.size
        for subnet, interface in self.routeTable.iteritems():
            if ((IP in subnet) and (subnet.size <= bestMatchSubnet.size)):
                bestMatchInterface = interface
                bestMatchSubnet = subnet
#                bestMatchSize = subnet.size
        return bestMatchInterface
    
    def getIPZone(self,IP):
        #get routeInterface for IP and check the configFile for the Zone for this interface retun Zone
        interface = self.getRouteInterface(IP)
        zone = None
        if (interface == None):
            raise ValueError('No route found for this IP! please add route to the '+self.name+'_routes file and try again')
        for line in self.configFile:
            if (line.find("set security zones security-zone") != -1 ) and (line.find(interface) != -1):
                zone = line.split()[4]
        return zone
    
    def getAddressNames(self,zone,IP):
        #return addressNames
        #set security zones security-zone gsm address-book address 172.23.37.211/32
        addressNames = []
        for line in self.configFile:
            if (line.find("set security zones security-zone "+zone+" address-book address ") != -1 ) and (line.split()[-1] == str(IP)):
                addressNames.append(line.split()[-2])
        return addressNames
    
    def createAddress(self,addressName,zone,IP):
        #return config for address in the created config list and add it to the local file and config list
        line = "set security zones security-zone "+zone+" address-book address "+addressName+" "+str(IP)
        self.createdConfig.append(line)
        self.configFile.append(line)
        WriteFile(self.name,['\n',line])#add line to current config file
        return
    
    def getAppNames(self,startPort,endPort,protocol):
        # app ports could be written in 2 ways 222 or 222-222 so we check for both and then check for protocol return appNames
        #set applications application TCP_2462 term TCP_2462 protocol tcp
        #set applications application TCP_2462 term TCP_2462 source-port 0-65535
        #set applications application TCP_2462 term TCP_2462 destination-port 2462-2462
        if(startPort == endPort == protocol):
            return 'junos-'+protocol
        appName = None
        if (startPort == endPort):
            appNameStr = [startPort,startPort+"-"+endPort]
        else:
            appNameStr = [startPort+"-"+endPort]
        for line in self.configFile:
            if (line.find("set applications application ") != -1 ) and (line.split()[-1] in appNameStr):
                potentialName = line.split()[3]
                for line in self.configFile:
                    if (line.find("set applications application "+potentialName) != -1 ) and (line.split()[-1] == protocol):
                        appName = potentialName
        return appName
    
    def createApp(self,startPort,endPort,protocol,appName=None):
        #return app config
        if (not appName):
            if (startPort == endPort):
                appName = protocol.upper()+"_"+startPort
            else:
                appName = protocol.upper()+"_"+startPort+"-"+endPort
                
        lines = ["set applications application "+appName+" term "+appName+" protocol "+protocol,
                 "set applications application "+appName+" term "+appName+" source-port 0-65535",
                 "set applications application "+appName+" term "+appName+" destination-port "+startPort+"-"+endPort]
        self.createdConfig += lines
        self.configFile += lines
        WriteFile(self.name,lines)
        return appName
    
    def createPolicy(self,policyName,sourceZone,sourceAddressNames,destinationZone,destinationAddressNames,appNames):
        #add config of policy

        
        lines = []
        for source in sourceAddressNames:
            lines.append("set security policies from-zone "+sourceZone+" to-zone "+destinationZone+" policy "+policyName+" match source-address "+source)
        for destination in destinationAddressNames:
            lines.append("set security policies from-zone "+sourceZone+" to-zone "+destinationZone+" policy "+policyName+" match destination-address "+destination)
        for app in appNames:
            lines.append("set security policies from-zone "+sourceZone+" to-zone "+destinationZone+" policy "+policyName+" match application "+app)
        lines.append("set security policies from-zone "+sourceZone+" to-zone "+destinationZone+" policy "+policyName+" then permit")
        lines.append("set security policies from-zone "+sourceZone+" to-zone "+destinationZone+" policy "+policyName+" then log session-init")
        self.createdConfig += lines
        self.configFile += lines
        WriteFile(self.name,lines)        
        return
    

    def getAddressNamesIncludingIP(self,zone,IP):
        #return all addesses/address Groups that includes the IP
        addressNames = []
        for line in self.configFile:
            if (line.find("set security zones security-zone "+zone+" address-book address ") != -1 ):
                if (IP in netaddr.IPNetwork(line.split()[-1])):
                    addressNames.append(line.split()[-2])
        for address in addressNames:
            for line in self.configFile:
                    if (line.find("set security zones security-zone "+zone+" address-book address-set ") != -1 and (line.split()[-1] in addressNames)):
                        addressNames.append(line.split()[-3])
                
        return addressNames
    
    def getPolicy(self,sourceZone=None,sourceIPs=None,destinationZone=None,destinationIPs=None,appNames=None):
        policies=[]
        
        
    #################Specific for SRX##########################################################################################
    def getPolicyWithWord(self,word):
        out = []
        lineIndex = 0
        while (lineIndex < len(self.configFile)):
            if (self.configFile[lineIndex].find(word) != -1 ):
                    out.append(self.configFile[lineIndex])
            lineIndex += 1
        return out
    
    
if __name__ == "__main__":
    ip = netaddr.IPNetwork('10.230.99.172')
#    print (str(ip))
    f = SRX("","","","",ReadFile('SF.txt'),ReadFile('SF_routes.txt'))