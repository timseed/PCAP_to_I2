import daiquiri
from datetime import datetime
from scapy.all import *
import socket


class Socket_Name(object):
    '''
    Get the Name of a Port
    '''

    def name(self, socket_number):
        '''

        :param socket_number:
        :return:
        '''
        try:
            socket_number = int(socket_number)
            sock_name = socket.getservbyport(socket_number)
            return sock_name
        except:
            if int(socket_number)==5220:
                return "Stun"
            else:
                return "Unk"

class Host_Name(object):

    '''
    Get the local of DNS Registered name
    '''
    def name(self,ip):
        try:
            (name, aliaslist, addresslist) = socket.gethostbyaddr(ip)
            return name, aliaslist, addresslist
        except:
            return "Unk",["Unk"],["Unk"]



class PCAP2I2(object):
    '''
    Class to Read and extract data from PCAP file.
    Purpose is to feed an import in IBM's I2 product
    '''

    def __init__(self, file,myhostsfile):
        '''
        Create PCAP Reader Class

        :param file:
        '''

        self.logger = daiquiri.getLogger(str(type(self)))
        self.logger.info("Starting {}".format(__name__))
        self._file = file
        self._pcap = None
        self.first_time = True
        self._unique_ips = {}  # A Dictionary of Host IPS
        self._unique_sockets = {}  # A Dictionary of Sockets with their English Description
        self.sname = Socket_Name()
        self.host = Host_Name()

        #When I run this these are the known IP's from my testing Setup
        self._unique_ips={}
        self._my_unique_ips={}

        if len(myhostsfile):
            self.load_my_hosts(myhostsfile)
        self.readpcap()  # setup the reader

    def load_my_hosts(self,hosts_file):
        '''
        Load a file of IP<Space>NAME into an internal data structure.

        :param hosts_file: A filename (if it is supplied)
        :return:
        '''

        self.logger.debug("in load_my_hosts file: {}".format(hosts_file))
        try:
            with open(hosts_file,"rt") as hostfile:
                for line in hostfile:

                    ip,name = line.strip().split()
                    self._my_unique_ips[ip]=name
                    self.logger.debug("Added {} {}".format(ip,name))
        except:
            pass

    def check_add_ip(self, ip):
        '''
        Check to see if an IP is in the list of Unique IPs
        If it is - ignore
        else check if it is in "Our" Private IP List in which case add it - else look on the Net

        :param ip: string representing an IP Address
        :return: None
        '''

        ip = str(ip).strip()
        if ip not in self._unique_ips:
            if ip in self._my_unique_ips:
                self._unique_ips[ip]=self._my_unique_ips[ip]
            else:
                name, aliaslist, addresslist = self.host.name(ip)
                self._unique_ips[ip] = name


    def check_add_socket(self, port):
        '''
        Check to see if the Socket is unique
        If it is not in the list use the Sock_Name class to get the "English" Description of the Socket
        :param port:
        :return:
        '''

        if port not in self._unique_sockets:
            # self.logger.debug("Checking port {}".format(port))
            port_name = self.sname.name(port)
            if port_name != "Unk":
                self._unique_sockets[str(port)] = port_name
        else:
            self.logger.debug("Ignored port {}".format(port))

    def readpcap(self):
        '''
        This is called by the constructor do not use.

        :return:
        '''
        self.logger.info("Creating Pcap Reader")
        try:
            self._pcap = rdpcap(self._file)
            self.logger.debug("Reader created Ok")
            return True
        except Exception as err:
            self.logger.error("Error Creating PcapReader for {} Err: {}".format(self._file, str(err)))
            return False

    def packets_out(self, filter_ip=[],omit_unknown=False):
        '''
        This is a Generator used like

        for rec in I2_out():
            dosomething (rec)

        :param filter_ip: A list of wanted IP Addresses; If the oist is Empty then Accept everything, else filter on
        the source or Destination IP Address

        :return: A text String CSV Delimited
        '''

        self.logger.info("in I2_OUT")
        header = "{},{},{:<20},{:<20},Type,{:<7},{:<7}".format("Date", "Time", "src", "dst", "sport", "dport")
        for p in self._pcap:
            txt = ""
            ipmatch = False
            if p.haslayer(IP):
                txt = "{},{},{:<20},{:<20},".format(datetime.fromtimestamp(p.time).strftime('%Y-%m-%d'),
                                                    datetime.fromtimestamp(p.time).strftime('%H:%M:%S'),
                                                    p[IP].src,
                                                    p[IP].dst)
                if len(filter_ip) > 0:
                    if p[IP].src in filter_ip or p[IP].dst in filter_ip:
                        ipmatch = True
                else:
                    ipmatch = True
                if p.haslayer(TCP):
                    txt += "TCP ,{:<7},{:<7}".format(p[TCP].sport, p[TCP].dport)
                elif p.haslayer(UDP):
                    txt += "UDP ,{:<7},{:<7}".format(p[UDP].sport, p[UDP].dport)
                else:
                    txt += "UNK ,{:<7},{:<7}".format("0", "0")
                    if omit_unknown:
                        ipmatch=False
                # We need to make sure we have one of the IP Strings in the txt

                if ipmatch == True:

                    self.check_add_ip(p[IP].src)
                    self.check_add_ip(p[IP].dst)
                    if p.haslayer(TCP):
                        self.check_add_socket(p[TCP].sport)
                        self.check_add_socket(p[TCP].dport)
                    elif p.haslayer(UDP):
                        self.check_add_socket(p[UDP].sport)
                        self.check_add_socket(p[UDP].dport)

                    if self.first_time == True:
                        txt = header + "\n" + txt
                        self.first_time = FREEBSD
                    yield (txt)

    def hosts_out(self):
        '''
        Generator for hosts
        :return: string looking like ip,name
        '''
        first_time = True
        for k in self._unique_ips.keys():
            if first_time:
                pre = "Host_IP,Name\n"
                first_time = False
            else:
                pre = ""
            yield pre + "{},{}".format(k, self._unique_ips[k])

    def sockets_out(self):
        '''
        Generator for ports
        :return: string looking like port,name
        '''
        first_time = True
        for k in self._unique_sockets.keys():
            if first_time:
                pre = "Socket,Name\n"
                first_time = False
            else:
                pre = ""
            yield pre + "{},{}".format(k, self._unique_sockets[k])
