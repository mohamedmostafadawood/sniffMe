import socket
import struct
import textwrap

#unpacking ethernet frame
def unpackEthernetFrame(data):
    destMac, srcMac, protocol = struct.unpack("! 6s 6s H", data[:14])
    return getMacAddress(destMac), getMacAddress(srcMac), socket.htons(protocol), data[14:]
