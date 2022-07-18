from msilib import sequence
import socket
import struct
import textwrap




#For "\t ", it’s a tab/indent if used in a string (i.e. a sequence of characters, forming a text).
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


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
        
        # In ethernet frame, if the 2 bytes related to type is 0x0800 so it is IPv4
        if ethProtocol == 8 :
            # The data extracted from the Ethernet Frame will be unpacked as IPv4 packet
            version, header_length, ttl, ipProtocol, srcIP, dstIP = unpackIPv4Datagrams(data)
            print(TAB_1, "IPv4 Packet:")
            print(TAB_2, "Version {}, Header Length {}, Time to live {}".format(version, header_length, ttl))
            print(TAB_2, "IP Protocol type {}".format(ipProtocol))
            print(TAB_2, "Source IP {}, Destination IP {}".format(srcIP, dstIP))
            
            
            # I will check the ipProtocol variable and based on its value I can know what type of
            
            


        
        
        
        
        
        
        
        
        
        
        
# Unpacking ethernet frame

def unpackEthernetFrame(data):
    destMac, srcMac, protocol = struct.unpack("! 6s 6s H", data[:14])
    return getMacAddress(destMac), getMacAddress(srcMac), socket.htons(protocol), data[14:]


# Return properly formatted MAC address (Example: FF:FF:FF:FF:FF:FF)

def getMacAddress(macAddInBytes):
    strMac = map("{:02x}".format, macAddInBytes)
    return ':'.join(strMac).upper()


# Unpacking IPv4 Datagram(Header)

def unpackIPv4Datagrams(data):
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
    return version, header_length, ttl, ipProtocol, srcIP, dstIP 
    
    
    
# Return properly formatted MAC address (Example: 192.168.1.1)

def getIpAddress (ip):
    return '.'.join(map(str,ip))
    


# Unpakcing ICMP packets

def icmpPacket(data):
    type, code, checksum = struct.unpack("! B B H", data[:4])
    return  type, code, checksum, data[4:]
    

# Unpacking TCP segment

def tcpSegment(data):
    scrPort, dstPort, sequenceNo, ackNo, offsetAndReservedFlags = struct.unpack("! H H L L H", data[:14])
    #offset is the same as tcp header length.
    tcpHeaderLength = (offsetAndReservedFlags >> 12) * 4 #shift right by 12 to get only the first 4 bits and convert it from words to bytes by *4
    
    # for the reserved flags, they are 6 consecutive bits. To be precise, they are the last 6 bits in the 16 bits of offsetAndReservedFlags variable(It is a 2 byte one.)
    #For example, I want to extract the URG flag bit which is the 6 bit from the last. For example this is the offsetAndReservedFlags(0100 0100 1111 1011)
    #I need to extract the bit number 6 from last, so I will and it with a number that have only 1 at this position while the other are zeros.
    #I will and it with 32 (0000 0000 0010 0000)
    #Then, I will shift it 5 to the right to keep only the bit number 6 as my LSB.
    urgFlag = ( offsetAndReservedFlags & 32 ) >> 5
    
    #The same process will be applied for the rest of flags but with some modifications based on flag bits' position.
    ackFlag = ( offsetAndReservedFlags & 16 ) >> 4
    pshFlag = ( offsetAndReservedFlags & 8 ) >> 3
    rstFlag = ( offsetAndReservedFlags & 4 ) >> 2
    synFlag = ( offsetAndReservedFlags & 2 ) >> 2
    finFlag = ( offsetAndReservedFlags & 1 ) 

    return scrPort, dstPort, sequenceNo, ackNo, ackFlag, pshFlag, rstFlag, synFlag, finFlag, data[tcpHeaderLength:]
    
    


# Unpacking UDP segments

def udpSegment(data):
    srcPort, dstPort, size = struct.unpack("! H H H" , data[:6])
    return srcPort, dstPort, size, data[8:]
    
    
    

# Formatting multi-line data

def formaMultiLine(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()