from enum import Enum
from dataclasses import dataclass
import struct
import binascii
import socket
from collections import namedtuple

class PacketType(Enum):
    PT_ASKINFO         = 12
    PT_SERVERINFO      = 13
    PT_PLAYERINFO      = 14
    PT_TELLFILESNEEDED = 34
    PT_MOREFILESNEEDED = 35

def checksum(buf):
    c = 0x1234567
    for i, b in enumerate(buf):
        c += b * (i+1)
    return c

packet_formats = {
    PacketType.PT_PLAYERINFO: {
        "format": "B22s4sBBBIH",
        "fields": "num name address team skin data score timeinserver"
    }
}

def decode_string(byte_list):
    string = ""
    for b in byte_list:
        if b == 0:
            break
        if b <= 128:
            string += chr(b)
    return string

@dataclass
class Packet:
    type: PacketType

    def pack(self):
        if (self.type == PacketType.PT_ASKINFO):
            u = struct.pack("x"*5)
        else:
            raise Exception("Unknown type")
        pkt = struct.pack("xxBx", self.type.value) + u
        return struct.pack('<L', checksum(pkt)) + pkt

    def _add_to_dict(self, d):
        for k,v in d.items():
            self.__dict__[k] = v

    def unpack_common(self, pkt):
        """
        Unpack the first part of the packet, which is the same for every packet type.
        """
        header_length = 8
        format = "IBBBB"
        fields = "checksum ack ackreturn packettype reserved"
        t = namedtuple('Packet', fields)
        unpacked = t._asdict(t._make(struct.unpack(format, pkt[:header_length])))
        self._add_to_dict(unpacked)
        return pkt[header_length:]


class ServerInfoPacket(Packet):
    def __init__(self, pkt):
        self.type = PacketType.PT_SERVERINFO
        self.unpack(pkt)

    def unpack(self, pkt):
        pkt = self.unpack_common(pkt)
        format_length = 150
        format = "<BB16sBBBBB24sBBBBII32s8s33s16sBB"
        fields = "x_255 packetversion application version subversion numberofplayer maxplayer refusereason gametypename modifiedgame cheatsenabled isdedicated fileneedednum time leveltime servername mapname maptitle mapmd5 actnum iszone"
        string_fields = ["application", "gametypename", "servername", "mapname", "maptitle"]
        t = namedtuple('Packet', fields)
        unpacked = t._asdict(t._make(struct.unpack(format, pkt[:format_length])))
        for s in string_fields:
            unpacked[s] = decode_string(unpacked[s])
        self._add_to_dict(unpacked)
        self.fileneeded = pkt[format_length:]

class SRB2Query:
    def __init__(self, url="localhost", port=5029):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect((url, port))

    def send(self, request):
        self.socket.sendall(request.pack())

    def recv(self):
        data = bytearray()
        buff_size = 1024
        while True:
            new_data = self.socket.recv(buff_size)
            data += new_data
            if len(new_data) < buff_size:
                break
        return data

    def askinfo(self):
        pkt = Packet(PacketType.PT_ASKINFO)
        self.send(pkt)
        resp = ServerInfoPacket(self.recv())
        return resp

q = SRB2Query("srb2circuit.eu")
resp = q.askinfo()
