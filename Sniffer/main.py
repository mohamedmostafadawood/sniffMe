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
        #print("\nEthernet Frame:")
        #print("DestinationMac {}, Source Mac {}, Ethernet Protocol {}".format(destMac, srcMac, ethProtocol))
        
# Unpacking ethernet frame

def unpackEthernetFrame(data):
    destMac, srcMac, protocol = struct.unpack("! 6s 6s H", data[:14])
    return getMacAddress(destMac), getMacAddress(srcMac), socket.htons(protocol), data[14:]


# Return properly formatted MAC address (Example: FF:FF:FF:FF:FF:FF)

def getMacAddress(macAddInBytes):
    strMac = map("{:02x}".format, macAddInBytes)
    return ':'.join(strMac).upper()


# Unpacking IPv4 packets

def unpackIPv4Packets(data):
    version_header_length = data[0] #because they both are 8 bits which are the first byte of the data
    version = version_header_length >> 4 #shift right by 4 to get the version only out of the combined 8 bits
    
    
    # If anyone is wondering why did I use (version_header_length & 15 ). Here's the reason:
    #lets assume: #version_header_length = 10101101. #15 = 00001111 # bitwise representation
    #version_header_length & 15 = 00001101 which is same as 1101. So, we get the header_length only.
    
    #Header Length: this 4 bit field tells us the length of the IP header in 32 bit increments.
    #The minimum length of an IP header is 20 bytes so with 32 bit increments, you would see value of 5 here.
    # The maximum value we can create with 4 bits is 15 so with 32 bit increments, that would be a header length of 60 bytes.#This field is also called the Internet Header Length (IHL)
    # So, you take this 4 bits field and convert it to decimal. The decimal number you have is how many words is our header_lenght.
    # Then, I mutliply it by 4 to convert it from words to bytes to address the start of your payload properly.
    header_length = (version_header_length & 15) * 4
    
    #I access the first 20 bytes which are the main compenents of the IPv4 header format.
    #I ignore the first 8 bytes of the header as I am not interested in them now.
    #Then, a byte for ttl, a byte for protocol, ignoring the 2 bytes of the checksum, and 4 bytes for each IP address (Source and destination).
    ttl, ipProtocol, srcIP, dstIP = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    
    
    
    
    







main()