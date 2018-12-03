//
//  RawPacket.m
//  VisualSniff
//
//  Created by David Hoelzer on 10/6/11.
//  Copyright 2011 Enclave Forensics, Inc. All rights reserved.
//

#import "RawPacket.h"

@implementation RawPacket
@synthesize rawPacketData, packetSize;

- (id)initWithPacket:(const u_char *)packet_data length:(int)packetLength
{
    self = [super init];
    if (self) {
        rawPacketData = packet_data; // This should be a copy...
        packetSize = packetLength;
    }
    return self;
    
}

-(int) getIPTotalLength
{
    int x;
    const u_char *IP_Header = &(self.rawPacketData[14]);
    
    x = IP_Header[2] << 8;
    x |= IP_Header[3];
    return x;
}

-(int) getUDPLength
{
    int x;
    const u_char *UDP_Header = &(self.rawPacketData[14]);
    
    x = UDP_Header[5] << 8;
    x |= UDP_Header[4];
    return x;
}

- (BOOL)isIP
{
    NSString *etherType = [NSString stringWithFormat:@"0x%x%x", self.rawPacketData[12], self.rawPacketData[13]];
    return [etherType isEqualToString:@"0x80"];
}

- (int)getPayloadSize
{
    int totalHeaders;
    int x;
    const u_char *IP_Header = &(self.rawPacketData[14]);
    
    totalHeaders = 14; // Ethernet header
    x = IP_Header[0] & 0x0f; // Determine IP Header Length
    x = x << 2;
    totalHeaders +=  x;
    switch (IP_Header[9]) {
        case 6:
            totalHeaders += 20; // Not dealing with TCP options for now
            x = [self getIPTotalLength];
            break;
        case 17:
            totalHeaders += 8; // UDP
            x = [self getUDPLength];
            break;
        default:
            return 1024;
            // Only looking at TCP and UDP for now.
            break;
    }
    return (x);
}

-(NSString *)getEtherSourceHost
{
    char source[24];
    sprintf(source, "%x:%x:%x:%x:%x:%x", self.rawPacketData[6], self.rawPacketData[7], 
            self.rawPacketData[8], self.rawPacketData[9], self.rawPacketData[10], self.rawPacketData[11]);
    
    NSString *nsSource = [NSString stringWithFormat:@"%s", source];
    
    return nsSource;
}

-(NSString *)getIPSourceHost
{
    char address[16]; //(> 3 * 4 + 3)
    const u_char *IP_Header = &(self.rawPacketData[14]);
    sprintf(address, "%d.%d.%d.%d", IP_Header[12], IP_Header[13], IP_Header[14], IP_Header[15]);
    NSString *result = [NSString stringWithFormat:@"%s", address];
    return result;
}

-(NSString *)getIPDestinationHost
{
    char address[16]; //(> 3 * 4 + 3)
    const u_char *IP_Header = &(self.rawPacketData[14]);
    sprintf(address, "%d.%d.%d.%d", IP_Header[16], IP_Header[17], IP_Header[18], IP_Header[19]);
    NSString *result = [NSString stringWithFormat:@"%s", address];
    return result;
}


-(NSString *)getEtherDestinationHost
{
    char dest[24];
    sprintf(dest, "%x:%x:%x:%x:%x:%x", self.rawPacketData[0], self.rawPacketData[1], 
            self.rawPacketData[2], self.rawPacketData[3], self.rawPacketData[4], self.rawPacketData[5]);
    
    NSString *nsDest = [NSString stringWithFormat:@"%s", dest];
    
    return nsDest;
}

@end
