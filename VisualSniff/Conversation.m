//
//  Conversation.m
//  VisualSniff
//
//  Created by David Hoelzer on 10/15/11.
//  Copyright 2011 Enclave Forensics, Inc. All rights reserved.
//

#import "Conversation.h"
#import "Host.h"

@implementation Conversation
@synthesize sourceHost, destinationHost, packets, idTag, size, lastPacket;

-(float) adjustedPackets
{
    return (logf(packets));
}

-(float) adjustedSize
{
    return (logf(size));
}

- (NSInteger)lastPacketReceived
{
    return ([lastPacket timeIntervalSinceNow] * -1 );
}

-(void)addPacket
{
    packets += 1;
    packets = (packets > 250 ? 250 : packets);
    [lastPacket release];
    lastPacket = [[NSDate alloc] init];
}

-(void)addSize:(int)bytes
{
    size += bytes;
    size = (size > 250 ? 250 : size);
}

-(void) reducePackets:(float)factor
{
    packets = packets * factor;
    packets = (packets < 1 ? 0 : packets);
}

-(void) reduceSize:(float)factor
{
    size = size * factor;
    size = (size < 1 ? 0 : size);
}

- (id)init
{
    self = [super init];
    if (self) {
        packets = 0;
    }
    
    return self;
}

@end
