import socket
import struct
import textwrap


# unpacking ethernet frame

def unpackEthernetFrame(data):
    destMac, srcMac, protocol = struct.unpack("! 6s 6s H", data[:14])
    return getMacAddress(destMac), getMacAddress(srcMac), socket.htons(protocol), data[14:]


# Return properly formatted MAC address (Example: FF:FF:FF:FF:FF:FF)

def getMacAddress(macAddInBytes):
    strMac = map(":02x".format, macAddInBytes)
    return ':'.join(strMac).upper()
