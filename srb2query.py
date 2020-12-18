from enum import Enum
from dataclasses import dataclass
import struct
import socket
from collections import namedtuple

def get_map_title(title, iszone, actnum):
    mapname = title
    if iszone:
        mapname += " zone"
    if actnum:
        mapname += f" {actnum}"
    return mapname

def char_to_num(char):
    return ord(char) - ord("A")

def num_to_char(num):
    return chr(num + ord("A"))

def mapname_to_num(mapname):
    if not mapname:
        return 0
    name = mapname[3:] # remove "MAP"
    try:
        num = int(name)
        return num
    except ValueError:
        p = char_to_num(name[0])
        try:
            q = int(name[1])
        except ValueError:
            q = 10 + char_to_num(name[1])
        return ((36*p + q) + 100)

def mapnum_to_name(mapnum):
    if mapnum < 100:
        return "MAP" + str(mapnum)
    mapnum -= 100
    p, q = divmod(mapnum, 36)
    p = num_to_char(p)
    if q >= 10:
        q = num_to_char(q-10)
    return f"MAP{p}{q}"

num_to_skin = {
    0: "sonic",
    1: "tails",
    2: "knuckles",
    3: "amy",
    4: "fang",
    5: "metalsonic",
}

class PacketType(Enum):
    PT_ASKINFO         = 12
    PT_SERVERINFO      = 13
    PT_PLAYERINFO      = 14
    PT_TELLFILESNEEDED = 34
    PT_MOREFILESNEEDED = 35

NETFIL_WILLSEND = 16
NETFIL_WONTSEND = 32

def checksum(buf):
    """
    @param buf: buffer without the checksum part
    """
    c = 0x1234567
    for i, b in enumerate(buf):
        c += b * (i+1)
    return c

def checksum_match(buf, checksum):
    """
    Returns the index at which the checksum matches
    Or False if the checksum matches never
    @param buf: buffer including the checksum part
    """
    c = 0x1234567
    for i, b in enumerate(buf[4:]):
        c += b * (i+1)
        if (c == checksum):
            return i+4
    return False


def decode_string(byte_list):
    string = ""
    for b in byte_list:
        if b == 0:
            break
        if b < 128:
            string += chr(b)
    return string

def unpack_into(pkt, format, fields):
    t = namedtuple('Packet', fields)
    unpacked = t._asdict(t._make(struct.unpack(format, pkt)))
    return unpacked

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

    def unpack_fileneeded(self, fileneeded):
        files = []
        offset = 0
        for i in range(self.fileneedednum):
            format = "<BI"
            format_length = 5
            fields = "status size"
            unpacked = unpack_into(fileneeded[offset:offset+format_length], format, fields)
            offset += format_length
            unpacked['name'] = decode_string(fileneeded[offset:])
            offset += len(unpacked['name'])+1
            unpacked['md5sum'] = fileneeded[offset:offset+16]
            offset += 16
            unpacked['toobig'] = not (unpacked['status'] & NETFIL_WILLSEND)
            unpacked['download'] = not(unpacked['toobig'] or unpacked['status'] & NETFIL_WONTSEND)
            files.append(unpacked)
        self.filesneeded = files

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
        unpacked['map'] =  {
            'num': mapname_to_num(unpacked['mapname']),
            'name': unpacked['mapname'],
            'title': get_map_title(unpacked['maptitle'], unpacked['iszone'], unpacked['actnum'])
        }
        self._add_to_dict(unpacked)
        self.unpack_fileneeded(pkt[format_length:])

class PlayerInfoPacket(Packet):

    def __init__(self, pkt):
        self.type = PacketType.PT_PLAYERINFO
        self.players = []
        self.unpack(pkt)

    def unpack(self, pkt):
        pkt = self.unpack_common(pkt)
        format_length = 36
        format = "<B22s4sBBBIH"
        fields = "num name address team skin data score timeinserver"
        for i in range(32):
            t = namedtuple('Packet', fields)
            unpacked = t._asdict(t._make(struct.unpack(format, pkt[:format_length])))
            if (unpacked['num'] < 255):
                unpacked['name'] = decode_string(unpacked['name'])
                unpacked['skin'] = num_to_skin.get(unpacked['skin'], "unknown")
                self.players.append(unpacked)
            pkt = pkt[format_length:]

class SRB2Query:
    data = bytearray()

    def __init__(self, url="localhost", port=5029):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect((url, port))

    def send(self, request):
        self.socket.sendall(request.pack())

    def recv(self):
        BUF_SIZE = 1450
        packet = self.socket.recv(BUF_SIZE)
        cs = struct.unpack("I", packet[:4])[0]
        if cs == checksum(packet[4:]):
            return packet
        else:
            raise Exception("Incorrect checksum")

    def askinfo(self):
        pkt = Packet(PacketType.PT_ASKINFO)
        self.send(pkt)
        serverinfo = ServerInfoPacket(self.recv())
        playerinfo = PlayerInfoPacket(self.recv())
        return serverinfo, playerinfo

if __name__ == "__main__":
    q = SRB2Query("localhost")
    serverpkt, playerpkt = q.askinfo()
    print(serverpkt.__dict__)
    print(playerpkt.__dict__)
