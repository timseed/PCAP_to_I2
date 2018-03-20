#!/usr/bin/env python3
from PCAP2I2 import PCAP2I2
from glob import glob
import daiquiri
import logging
import argparse


daiquiri.setup(outputs=(
    daiquiri.output.Syslog(),
    daiquiri.output.STDERR,
    daiquiri.output.File(directory=".")),
    level=logging.INFO)
logger = daiquiri.getLogger()


parser = argparse.ArgumentParser()
parser.add_argument("-data","--data", help="Data Directory i.e. ./data/*.pcapng",
                    default="./data/*.pcapng")
parser.add_argument("-myhosts","--myhosts",
                    help="A file of ip,host which will be used instead of DNS lookups. Default: Not used.",
                    default="",required=False)
args=parser.parse_args()


logger.debug("DataDir is {}".format(args.data))
logger.debug("Local Hosts File is <{}>".format(args.myhosts))
#
#Sample Data Parser for an PCAP File
#This will be rendered using I2 in a Custom Import Script in I2
#

files=glob(args.data)
for f in files:
    logger.info("{}".format(f))
    i2exp=PCAP2I2(f,args.myhosts)
    if len(args.myhosts)>1:
        logger.debug("Trying to load local hosts file {}".format(args.myhosts))
    try:
        with open(f+".csv","wt") as outfile:
            for ipRec in i2exp.packets_out(filter_ip=[]):
                outfile.write(ipRec+"\n")
    except:
        pass
    logger.info("Packets Processed")
    with open(f+".hosts.csv","wt") as outfile:
        for ipRec in i2exp.hosts_out():
            outfile.write(ipRec+"\n")
    logger.info("Hosts Processed")
    with open(f+".ports.csv","wt") as outfile:
        for ipRec in i2exp.sockets_out():
            outfile.write(ipRec+"\n")
    logger.info("Ports Processed")

logger.info("Finished Processing")
