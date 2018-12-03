//
//  Conversation.h
//  VisualSniff
//
//  Created by David Hoelzer on 10/15/11.
//  Copyright 2011 Enclave Forensics, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Host.h"

@interface Conversation : NSObject
{
    Host *sourceHost, *destinationHost;
    float size;
    NSDate *lastPacket;
    float packets;
    NSString *idTag;
}

@property(readwrite, retain) NSString *idTag;
@property(readwrite, retain) Host *sourceHost;
@property(readwrite, retain) Host *destinationHost;
@property(readonly) float packets;
@property(readonly) float size;
@property (nonatomic, readonly, retain) NSDate *lastPacket;

-(void)addPacket;
-(void)addSize:(int)bytes;
-(float) adjustedPackets;
-(float) adjustedSize;
-(void) reducePackets:(float)factor;
-(void) reduceSize:(float)factor;
- (NSInteger)lastPacketReceived;

@end
