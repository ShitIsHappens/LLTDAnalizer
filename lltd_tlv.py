from iana_iftype import IFTYPE
from scapy.all import *

TLV_TYPE_CLASS =  {
    0x00 : "LLTDEndOfProperty",
    0x01 : "LLTDHostId",
    0x02 : "LLTDCharacteristics",
    0x03 : "LLTDPhysicalMedium",
    0x04 : "LLTDWirelessMode",
    0x05 : "LLTD80211BSSID",
    0x06 : "LLTD80211SSID",
    0x07 : "LLTDIPv4Address",
    0x08 : "LLTDIPv6Address",
    0x09 : "LLTD80211MaximumOperationalRate",
    0x0A : "LLTDPerformanceCounterFrequency",
    0x0B : "LLTDUncknown",
    0x0C : "LLTDLinkSpeed",
    0x0D : "LLTD80211ReceivedSignalStrengthIndication",
    0x0E : "LLTDIconImage",
    0x0F : "LLTDMachineName",
    0x10 : "LLTDSupportInformation",
    0x11 : "LLTDFriendlyName",
    0x12 : "LLTDDeviceUniversallyUniqueIdentifier",
    0x13 : "LLTDHardwareID",
    0x14 : "LLTDQoSCharacteristics",
    0x15 : "LLTD80211PhysicalMedium",
    0x16 : "LLTDAPAssociationTable",
    0x17 : "LLTD0x17",
    0x18 : "LLTDDetailedIconImage",
    0x19 : "LLTDSeesListWorkingSet",
    0x1A : "LLTDComponentTable",
    0x1B : "LLTDRepeaterAPLineage",
    0x1C : "LLTDRepeaterAPTable",
}

TLV_TYPE =  {
    0x00 : "End-of-Property List marker",
    0x01 : "Host ID, that uniquely identifies the host on which the responder is running.",
    0x02 : "Characteristics",
    0x03 : "Physical Medium",
    0x04 : "Wireless Mode",
    0x05 : "802.11 Basic Service Set Identifier",
    0x06 : "802.11 Service Set Identifier",
    0x07 : "IPv4 Address",
    0x08 : "IPv6 Address",
    0x09 : "802.11 Maximum Operational Rate",
    0x0A : "Performance Counter Frequency",
    0x0B : "Uncknown",
    0x0C : "Link Speed",
    0x0D : "802.11 Received Signal Strength Indication",
    0x0E : "Icon Image",
    0x0F : "Machine Name",
    0x10 : "Support Information that identifies the device manufacturer's support information.",
    0x11 : "Friendly Name",
    0x12 : "Device Universally Unique Identifier",
    0x13 : "Hardware ID",
    0x14 : "QoS Characteristics",
    0x15 : "802.11 Physical Medium",
    0x16 : "AP Association Table",
    0x17 : "Type 0x17",
    0x18 : "Detailed Icon Image",
    0x19 : "Sees-List Working Set",
    0x1A : "Component Table",
    0x1B : "Repeater AP Lineage",
    0x1C : "Repeater AP Table",
}


def _LLTDGuessPayloadClass(p, **kargs):
    cls = Raw
    if len(p) >= 2:
        t = struct.unpack("!B", p[:1])[0]
        clsname = TLV_TYPE_CLASS.get(t, "LLTDGeneric")
        if (clsname in globals()):
            cls = globals()[clsname]
        else:
            print("!!! Not REgistered: " + clsname)

    return cls(p, **kargs)

class LLTDGeneric(Packet):
    name = "LLTD TLV Item"
    fields_desc = [ ByteEnumField("type", None, TLV_TYPE),
                    FieldLenField("length", None, "value", "!B"),
                    StrLenField("value", "", length_from=lambda x:x.length) ]

    def guess_payload_class(self, p):
        return Padding # _LLDPGuessPayloadClass

IEEE80211MODE =  {
    0x00 : "802.11 IBSS or ad-hoc mode",
    0x01 : "802.11 infrastructure mode"
}

class LLTDEndOfProperty(LLTDGeneric):
    name = "End-of-Property"
    fields_desc = [ByteEnumField("type", 0x00, TLV_TYPE)]

class LLTDHostId(LLTDGeneric):
    name = "Host ID"
    fields_desc = [ByteEnumField("type", 0x01, TLV_TYPE),
                   ByteField("length", 0x06),
                   MACField("macaddr", "00:11:11:11:11:11")]

class LLTDCharacteristics(LLTDGeneric):
    name = "Characteristics"
    fields_desc = [ByteEnumField("type", 0x02, TLV_TYPE),
                   ByteField("length", 0x04),
                   BitField("P", 0, 1),
                   BitField("X", 0, 1),
                   BitField("F", 0, 1),
                   BitField("M", 0, 1),
                   BitField("L", 0, 1),
                   ConditionalField(BitField("reserved", 0, 11), lambda pkt: pkt.length == 0x02),
                   ConditionalField(BitField("reserved", 0, 27), lambda pkt: pkt.length == 0x04)]

class LLTDPhysicalMedium (LLTDGeneric):
    name = "Physical Medium"
    fields_desc = [ByteEnumField("type", 0x03, TLV_TYPE),
                   ByteField("length", 0x04),
                   IntEnumField("physical_medium", 71, IFTYPE)]

class LLTDWirelessMode(LLTDGeneric):
    name = "Wireless Mode"
    fields_desc = [ByteEnumField("type", 0x04, TLV_TYPE),
                   ByteField("length", 0x01),
                   ByteEnumField("mode", 0x00, IEEE80211MODE)]

class LLTD80211BSSID(LLTDGeneric):
    name = "BSSID"
    fields_desc = [ByteEnumField("type", 0x05, TLV_TYPE),
                   ByteField("length", 0x06),
                   MACField("BSSID", "00:00:00:00:00:00")]

class LLTD80211SSID(LLTDGeneric):
    name = "SSID"
    fields_desc = [ByteEnumField("type", 0x06, TLV_TYPE),
                   FieldLenField("length", None, "ssid_string", "!B"),
                   StrLenField("ssid_string", "", length_from=lambda x: x.length)]

class LLTDIPv4Address(LLTDGeneric):
    name = "IPv4 Address"
    fields_desc = [ByteEnumField("type", 0x07, TLV_TYPE),
                   ByteField("length", 0x04),
                   IPField("ipv4_address", "192.168.1.1")]

class LLTDIPv6Address(LLTDGeneric):
    name = "IPv6 Address"
    fields_desc = [ByteEnumField("type", 0x08, TLV_TYPE),
                   ByteField("length", 0x10),
                   IP6Field("ipv6_address", "fe80::2e0:b6ff:fe01:3b7a")]

class LLTD80211MaximumOperationalRate(LLTDGeneric):
    name = "802.11 Maximum Operational Rate"
    fields_desc = [ByteEnumField("type", 0x09, TLV_TYPE),
                   ByteField("length", 0x02),
                   ShortField("rate", 0)]

class LLTDPerformanceCounterFrequency(LLTDGeneric):
    name = "Performance Counter Frequency"
    fields_desc = [ByteEnumField("type", 0x0A, TLV_TYPE),
                   ByteField("length", 0x08),
                   LongField("frequency", 0)]

class LLTDUncknown(LLTDGeneric):
    name = "Uncknown"
    fields_desc = [ByteEnumField("type", 0x0B, TLV_TYPE),
                   FieldLenField("length", None,"value", "!B"),
                   StrLenField("value", "", length_from=lambda x: x.length)]

class LLTDLinkSpeed(LLTDGeneric):
    name = "Link Speed"
    fields_desc = [ByteEnumField("type", 0x0C, TLV_TYPE),
                   ByteField("length", 0x04),
                   IntField("link_Speed", 0)]


class LLTD80211ReceivedSignalStrengthIndication(LLTDGeneric):
    name = "802.11 RSSI"
    fields_desc = [ByteEnumField("type", 0x0D, TLV_TYPE),
                   ByteField("length", 0x04),
                   IntField("rssi", 0)]


class LLTDIconImage(LLTDGeneric):
    name = "Icon Image"
    fields_desc = [ByteEnumField("type", 0x0E, TLV_TYPE),
                   ByteField("length", 0x00)]

class LLTDMachineName(LLTDGeneric):
    name = "Machine Name"
    fields_desc = [ByteEnumField("type", 0x0F, TLV_TYPE),
                   FieldLenField("length", None, "name", "!B"),
                   StrLenField("name", "", length_from=lambda x: x.length)]

class LLTDFriendlyName(LLTDGeneric):
    name = "Friendly Name"
    fields_desc = [ByteEnumField("type", 0x11, TLV_TYPE),
                   FieldLenField("length", None, "name", "!B"),
                   StrLenField("name", "", length_from=lambda x: x.length)]

class LLTDDeviceUniversallyUniqueIdentifier(LLTDGeneric):
    name = "Device UUID"
    fields_desc = [ByteEnumField("type", 0x12, TLV_TYPE),
                   FieldLenField("length", None, "uuid", "!B"),
                   StrLenField("uuid", "", length_from=lambda x: x.length)]


class LLTDQoSCharacteristics(LLTDGeneric):
    name = "QoS Characteristics"
    fields_desc = [ByteEnumField("type", 0x14, TLV_TYPE),
                   ByteField("length", 0x04),
                   BitField("E", 0, 1),
                   BitField("Q", 0, 1),
                   BitField("P", 0, 1),
                   ConditionalField(BitField("reserved", 0, 13), lambda pkt: pkt.length == 0x02),
                   ConditionalField(BitField("reserved", 0, 29), lambda pkt: pkt.length == 0x04)]


class LLTD80211PhysicalMedium(LLTDGeneric):
    name = "802.11 Physical Medium"
    fields_desc = [ByteEnumField("type", 0x15, TLV_TYPE),
                   ByteField("length", 0x01),
                   BitField("Unknown", 0, 1),
                   BitField("FHSS 2.4 gigahertz (GHz)", 0, 1),
                   BitField("DSSS 2.4 GHz", 0, 1),
                   BitField("IR Baseband", 0, 1),
                   BitField("OFDM 5 GHz", 0, 1),
                   BitField("HRDSSS", 0, 1),
                   BitField("ERP", 0, 1),
                   BitField("Reserved for future use", 0, 1),
                   StrLenField("reserved", "", length_from=lambda x: x.length-1)]

class LLTDAPAssociationTable(LLTDGeneric):
    name = "AP Association Table"
    fields_desc = [ByteEnumField("type", 0x16, TLV_TYPE),
                   ByteField("length", 0)]

class LLTD0x17(LLTDGeneric):
    name = "Type 0x17"
    fields_desc = [ByteEnumField("type", 0x17, TLV_TYPE),
                   FieldLenField("length", None,"value", "!B"),
                   StrLenField("value", "", length_from=lambda x: x.length)]

class LLTDDetailedIconImage(LLTDGeneric):
    name = "Detailed Icon Image"
    fields_desc = [ByteEnumField("type", 0x18, TLV_TYPE),
                   ByteField("length", 0x00)]


class LLTDSeesListWorkingSet(LLTDGeneric):
    name = "Sees List Working Set"
    fields_desc = [ByteEnumField("type", 0x19, TLV_TYPE),
                   ByteField("length", 0x02),
                   ShortField("max_entries", 0)]

class LLTDComponentTable(LLTDGeneric):
    name = "Component Table"
    fields_desc = [ByteEnumField("type", 0x1A, TLV_TYPE),
                   ByteField("length", 0x00)]

class LLTDRepeaterAPLineage(LLTDGeneric):
    name = "Repeater AP Lineage"
    fields_desc = [ByteEnumField("type", 0x1B, TLV_TYPE),
                   FieldLenField("length", None, "address", "!B"),
                   StrLenField("address", "", length_from=lambda x: x.length)]