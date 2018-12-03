//
//  EtherHost.h
//  VisualSniff
//
//  Created by David Hoelzer on 10/2/11.
//  Copyright 2011 Enclave Forensics, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Host : NSObject
{
    NSDate *lastPacket;
    NSString *address;
    struct CGColor *color;
    CGRect packetRect, sizeRect;
    float packets, size;
    float xCenter, yCenter;
    BOOL IP, ethernet;
}

- (id)initWithAddress:(NSString *)address;
- (CGPoint)setCenterX:(int)x Y:(int)y;
- (BOOL)isEthernet;
- (BOOL)isIP;
- (void)setEthernet;
- (void)setIP;
- (const char *)cStringAddress;
- (void)moveTo:(CGPoint)newCenter;
- (CGPoint)center;
- (void) reducePackets:(float)factor;
- (void) addPacket;
-(void) addSize:(int)bytes;
- (void) reduceSize:(float)factor;
- (NSInteger)lastPacketReceived;

@property (nonatomic, retain) NSDate *lastPacket;
@property (nonatomic, readwrite, retain) NSString *address;
@property (nonatomic, readwrite) struct CGColor *color;
@property (nonatomic, readonly) CGRect packetRect, sizeRect;
@property (nonatomic, readonly) float packets, size;
@property (nonatomic, readonly) BOOL IP, ethernet;
@end
