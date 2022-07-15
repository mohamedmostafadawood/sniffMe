import socket
import struct
import textwrap



def main():
    
    #For windows users, please run it with administration privileges.
    
    HOST = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((HOST,0))
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        rawData, address = conn.recvfrom(65536)
        destMac, srcMac, ethProtocol, data = unpackEthernetFrame(rawData)
        print("\nEthernet Frame:")
        print("DestinationMac {}, Source Mac {}, Ethernet Protocol {}".format(destMac, srcMac, ethProtocol))

# unpacking ethernet frame

def unpackEthernetFrame(data):
    destMac, srcMac, protocol = struct.unpack("! 6s 6s H", data[:14])
    return getMacAddress(destMac), getMacAddress(srcMac), socket.htons(protocol), data[14:]


# Return properly formatted MAC address (Example: FF:FF:FF:FF:FF:FF)

def getMacAddress(macAddInBytes):
    strMac = map("{:02x}".format, macAddInBytes)
    return ':'.join(strMac).upper()


main()