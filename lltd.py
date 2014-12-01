from scapy.all import *
from lltd_tlv import _LLTDGuessPayloadClass


SERVICE_TYPE = {
    0x00: "Topology discovery",
    0x01: "Quick discovery",
    0x02: "QoS diagnostics (Network Test and Cross Traffic Analysis)"
}

FUNCTION = {
    0x00: "Discover",          # Quick discovery
    0x01: "Hello",             # Quick discovery
    0x02: "Emit",
    0x03: "Train",
    0x04: "Probe",
    0x05: "Ack",
    0x06: "Query",
    0x07: "QueryResp",
    0x08: "Reset",             # Quick discovery
    0x09: "Charge",
    0x0A: "Flat",
    0x0B: "QueryLargeTlv",
    0x0C: "QueryLargeTlvResp"
}

EMIT_TYPE = {
    0x00: "Train",
    0x01: "Probe"
}

QUERY_TYPE = {
    0x00: "Probe",
    0x01: "ARP/ICMPv6"
}



class LltdHeader(Packet):
    name = "lltd Header"
    fields_desc = [ByteField("version", 0x01),
                   ByteEnumField("type", 0x00, SERVICE_TYPE),
                   ByteField("reserved", 0x00),
                   ByteEnumField("function", 0x00, FUNCTION)]


class LltdBaseHeader(Packet):
    name = "lltd Base Header"
    fields_desc = [MACField("real_destination_address", "00:00:00:00:00:00"),
                   MACField("real_source_address", "00:00:00:00:00:00"),
                   ShortField("sequence_number", 0x00)]


class DiscoverHeader(Packet):
    name = "Discover Upper-Level Header"
    fields_desc = [ShortField("generation_number", 0),
                   ShortField("number_of_stations", 0),
                   FieldListField("station_list", [], MACField("", "00:00:00:00:00:00"),
                                  count_from=lambda pkt: pkt.number_of_stations)]


class HelloHeader(Packet):
    name = "Hello Upper-Level Header"
    fields_desc = [ShortField("generation_number", 0),
                   MACField("current_mapper_address", "00:00:00:00:00:00"),
                   MACField("apparent_mapper_address", "00:00:00:00:00:00"),
                   PacketListField("tlv_list", [], _LLTDGuessPayloadClass)]


class EmitPacket(Packet):
    name = "Hello Upper-Level Header"
    fields_desc = [ByteEnumField("type", 0, EMIT_TYPE),
                   ByteField("pause", 0),
                   MACField("source", "00:00:00:00:00:00"),
                   MACField("destination", "00:00:00:00:00:00")]

class EmitHeader(Packet):
    name = "Hello Upper-Level Header"
    fields_desc = [FieldLenField("num", None, "emits", "!H"),
                   PacketListField("emits", [], EmitPacket, count_from=lambda x: x.num)]


class QueryRecveeDescs(Packet):
    name="RecveeDescs"
    fields_desc = [ShortEnumField("type", 0, QUERY_TYPE),
                   MACField("Real_Source_Address", "00:00:00:00:00:00"),
                   MACField("EthernetSource_Address", "00:00:00:00:00:00"),
                   MACField("Ethernet_Destination_Address", "00:00:00:00:00:00")]

    def guess_payload_class(self, p):
        return Padding


class QueryRecv(Packet):
    name = "QueryRecv"
    fields_desc = [BitField("M", 0, 1),
                   BitField("E", 0, 1),
                   BitField("num_descs", 0, 14),
                   PacketListField("RecveeDescs", [], QueryRecveeDescs, count_from=lambda pkt: pkt[QueryRecv].num_descs)]





#http://fossies.org/dox/scapy-2.2.0/classscapy_1_1fields_1_1Field.html