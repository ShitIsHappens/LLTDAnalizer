#! /usr/bin/env python
from time import sleep
import threading
import random

from packetbuilder import *


class SniffThread(threading.Thread):
    """Objects of this class creates a new threads
    where begin sniffing packets"""
    def __init__(self):
        self.sniffed_packets = list()
        threading.Thread.__init__(self)

    def run(self, timeout=7):
        """This function run sniffer"""

        self.sniffed_packets = sniff(filter="ether proto 0x88d9", timeout=timeout)


class LltdAnalyzer:

    def __init__(self, iface):
        self.iface = iface
        self.mac = get_if_hwaddr(iface)
        self.stations = dict()
        self.generation_number = 0xefa1
        self.mac_to_sec_num = dict()

    def reset(self):
        """This function broadcast three discovery frame."""
        sendp(build_reset_frame(src=self.mac))
        sleep(0.25)
        sendp(build_reset_frame(src=self.mac))
        sleep(0.25)
        sendp(build_reset_frame(src=self.mac))
        sleep(0.25)

    def get_stations(self):
        """This function"""
        bind_layers(Ether, LltdHeader, type=0x88D9)
        bind_layers(LltdHeader, LltdBaseHeader)
        #bind_layers(LltdBaseHeader, HelloHeader)

        conf.iface = self.iface

        sequence_number=0x4451

        discovery_frame=build_discovery_frame(src=self.mac, sec_num=sequence_number)# ok
        sendp(discovery_frame)

        pkts = sniff(filter="ether proto 0x88D9", timeout=5)    # We have Hello frames from other responders
        for pkt in pkts:

             if pkt[Ether].type == 0x88d9:
                 station_mac = pkt.getlayer(LltdBaseHeader).real_source_address
                 if not station_mac in self.stations:
                    self.stations[station_mac] = list()
                    self.mac_to_sec_num[station_mac]=0
                    self.stations[station_mac].append(pkt)

        print "Stations: ",
        for key in self.stations.keys():
            print key,
        print "\nGeneration number", self.generation_number

        sendp(build_hello_frame(src=self.mac))

        if len(self.stations)>0:

            stations_list = list()
            stations_list.append(self.mac)
            for responder in self.stations:
                stations_list.append(responder)
            sendp(build_discovery_frame(src=self.mac, gen_num=self.generation_number, sec_num=sequence_number, stations_list=stations_list))

            discovery_frame=build_discovery_frame(src=self.mac, sec_num=sequence_number, gen_num=self.generation_number)
            sendp(discovery_frame)
            sendp(discovery_frame)
            sendp(discovery_frame)
            sendp(discovery_frame)

    def generate_unique_mac_adr(self):
        """This function generates a unique MAC address in the range reserved Microsoft(000D3AD7F140-000D3AFFFFFF)"""
        random.seed()
        mac_addr = str(hex(random.randint(0x000D3AD7F140, 0x000D3AFFFFFF)))
        mac_addr = "00:0" + mac_addr[2:3] + ":" + mac_addr[3:5] + ":" +\
                   mac_addr[5:7] + ":" + mac_addr[7:9] + ":" + mac_addr[9:11]
        return mac_addr

    def send_and_receive_all_query_frames(self):
        """This function starts the sniffer-thread sends Query frames and receives QueryReceive frames
           After that it return recieved QueryReceive frames """
        thread_sniffer = SniffThread()
        thread_sniffer.start()

        for station in self.stations:
            query_frame = build_query_frame(dst=station, src=self.mac, sec_num=self.mac_to_sec_num[station])
            self.mac_to_sec_num[station]=increment_sec_num(self.mac_to_sec_num[station])
            sendp(query_frame)
            sleep(0.3)

        sleep(9)
        return thread_sniffer.sniffed_packets

    def send_probe_with_staff(self, who, src, dst):
        """This function generate EmitData, build Emit frames and send them """
        charge_packet =build_charge_frame(dst=who, src=self.mac)
        sendp(charge_packet)

        emits = []
        emit_data = EmitPacket(type=0x01, pause=0, source=src, destination=dst)
        emits.append(emit_data)
        emit_frame=build_enum_frame(dst=who, src=self.mac, data=emits, seq_num=self.mac_to_sec_num[who])
        sendp(emit_frame)

        self.mac_to_sec_num[who]=increment_sec_num(self.mac_to_sec_num[who])

    def cast(self, h1, h2):
        """ This function sends Probe frames to maper's responders and receive Query frames"""
        first_unique_mac = self.generate_unique_mac_adr()
        second_unique_mac = self.generate_unique_mac_adr()
        print "U1: ", first_unique_mac
        print "U2: ", second_unique_mac
        print "h1: ", h1
        print "h2: ", h2
        print '-----------------'

        self.send_probe_with_staff(h2, h2, h1)  # Probe1  h2: h2->h1

        self.send_probe_with_staff(h1, first_unique_mac, h2)  # Probe2  h1: u1->h2
        #self.send_probe_with_staff('00:1f:d0:5b:0f:66', '00:1f:d0:5b:0f:66', second_unique_mac)
        #Probe3  h1: u2->u1

        self.send_probe_with_staff(h1, second_unique_mac, first_unique_mac)
        #Probe4  h2: h2->u1

        self.send_probe_with_staff(h2, h2, first_unique_mac)



        query_receive = self.send_and_receive_all_query_frames()

        query_resp_list = list()
        for pkts in query_receive:
            if pkts.name=='Ethernet':
                if pkts[Ether].type == 0x88d9 and pkts[LltdHeader].function == 0x07:
                    print "QueryResp", pkts[Ether].src
                    print pkts[QueryRecv].show()
                    query_resp_list.append(pkts)

        result_list= list()
        for responder in query_resp_list:

            if responder[QueryRecv].num_descs != 0:

                for QueryDesc in responder[QueryRecv].RecveeDescs:

                    if QueryDesc.EthernetSource_Address == h2:
                        if QueryDesc.Ethernet_Destination_Address == first_unique_mac:
                            query_desc_list = [responder[Ether].src, QueryDesc]
                            result_list.append(query_desc_list)

        return result_list

    def discover(self):

        bind_layers(Ether, LltdHeader, type=0x88D9 )
        bind_layers(LltdHeader, LltdBaseHeader)
        bind_layers(LltdBaseHeader, QueryRecv)
        bind_layers(QueryRecv, QueryRecveeDescs)

        random.seed()
        for station in self.stations:
            sequence = random.randint(1, 128)
            self.mac_to_sec_num[station]=sequence

        #first_station = "00:24:1d:8f:a4:37"
        first_station = self.stations.keys()[0]
        log_file =open('DiscoverLog.txt', 'w')
        log_file.write("RSA-Real_Source_Address, ESA-Ethernet_Source_Address, EDA-Ethernet_Destination_Address \n")

        result_list=self.cast("00:24:1d:8f:a4:37", "00:1f:d0:5b:0f:66")
        for responder in result_list:
                    log_file.write("Ether:" + responder[0] + " ; ")
                    log_file.write("RSA:" + responder[1].Real_Source_Address + " ; ")
                    log_file.write("ESA:" + responder[1].EthernetSource_Address + " ; ")
                    log_file.write("EDA:" + responder[1].Ethernet_Destination_Address)
                    log_file.write("\n")
        """for station in self.stations:
            result_list=self.cast(first_station, station)

            for responder in result_list:
                    log_file.write("Ether:" + responder[0] + " ; ")
                    log_file.write("RSA:" + responder[1].Real_Source_Address + " ; ")
                    log_file.write("ESA:" + responder[1].EthernetSource_Address + " ; ")
                    log_file.write("EDA:" + responder[1].Ethernet_Destination_Address)
                    log_file.write("\n")
        log_file.close()"""


if __name__ == "__main__":
   #  my_macs = [get_if_hwaddr(i) for i in get_if_list()]
    anal = LltdAnalyzer("eth0")
    anal.reset()  # 1
    anal.get_stations()  # 1
    anal.discover()
    anal.reset()










