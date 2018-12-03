//
//  RawPacket.h
//  VisualSniff
//
//  Created by David Hoelzer on 10/6/11.
//  Copyright 2011 Enclave Forensics, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RawPacket : NSObject
{
    const u_char *rawPacketData;
    int packetSize;
}

- (id)initWithPacket:(const u_char *)packet_data length:(int)packetLength;
- (NSString *)getEtherDestinationHost;
- (NSString *)getEtherSourceHost;
- (NSString *)getIPSourceHost;
- (NSString *)getIPDestinationHost;
- (int)getPayloadSize;
- (BOOL)isIP;

@property(nonatomic,readonly)const u_char *rawPacketData;
@property(nonatomic, readonly)int packetSize;
@end
