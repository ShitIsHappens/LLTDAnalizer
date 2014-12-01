__author__ = 'root'
from lltd import *


def base_header(src="00:00:00:00:00:00", dst="FF:FF:FF:FF:FF:FF", func=0x00):
        return Ether(dst=dst, src=src, type=0x88D9)/LltdHeader(function=func)/LltdBaseHeader(real_source_address=src, real_destination_address=dst)


def build_emit_packet (emits,src="00:00:00:00:00:00" , dst="FF:FF:FF:FF:FF:FF",sec_num =0):
        base_lltd_leayers = Ether(src=src, dst=dst, type=0x88D9)/LltdHeader(function=0x02)/LltdBaseHeader(real_source_address=src, real_destination_address=dst, sequence_number=sec_num)
        emit_layers = EmitHeader(Num_Descs=emits.__len__(), EmiteeDescs=emits)
        return base_lltd_leayers/emit_layers


def build_charge_packet (src="00:00:00:00:00:00", dst="FF:FF:FF:FF:FF:FF"):
        return Ether(dst=dst, src=src, type=0x88D9)/LltdHeader(function=0x09)/LltdBaseHeader(real_source_address=src, real_destination_address=dst)


def build_query_packet (src="00:00:00:00:00:00", dst="FF:FF:FF:FF:FF:FF", sec_num=0):
        return Ether(dst=dst, src=src, type=0x88D9)/LltdHeader(version=0x01,function=0x06)/LltdBaseHeader(real_source_address=src, real_destination_address=dst, sequence_number=sec_num)