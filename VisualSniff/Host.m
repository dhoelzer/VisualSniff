//
//  EtherHost.m
//  VisualSniff
//
//  Created by David Hoelzer on 10/2/11.
//  Copyright 2011 Enclave Forensics, Inc. All rights reserved.
//

#import "Host.h"

@implementation Host
@synthesize address;
@synthesize packets;
@synthesize size;
@synthesize lastPacket;
@synthesize color;
@synthesize packetRect, sizeRect;
@synthesize ethernet, IP;




- (id)initWithAddress:(NSString *)my_address
{
    self = [super init];
    if (self) {
        self.address = [my_address copy];
        [self setCenterX:0 Y:0];
        ethernet = IP = NO;
        sizeRect = CGRectMake(-150, -150, 5, 5);
        packetRect = CGRectMake(-150, -150, 5, 5);
        color = CGColorCreateGenericRGB(0.9, 0.9, 0.1, 1.0);
        lastPacket = [[NSDate alloc] init];
    }
    return self;
}

- (NSInteger)lastPacketReceived
{
    return ([lastPacket timeIntervalSinceNow] * -1 );
}

- (void)moveTo:(CGPoint)newCenter
{
    CGPoint center;
    center = newCenter;
    sizeRect.origin.x = center.x - (sizeRect.size.width / 2);
    sizeRect.origin.y = center.y - (sizeRect.size.height / 2);
    packetRect.origin.x = center.x - (packetRect.size.width / 2);
    packetRect.origin.y = center.y - (packetRect.size.height / 2);
    
    xCenter = center.x;
    yCenter = center.y;
}

- (const char *)cStringAddress
{
    return [address cStringUsingEncoding:NSASCIIStringEncoding];
}

- (BOOL)isEthernet
{
    return ethernet;
}

-(void)adjustRectSizePackets
{
    float packetFactor = logf(packets);
    packetRect.size.width = (packetFactor >= 1 ? 12 + (packetFactor) : 12);
    packetRect.size.height = (packetFactor >= 1 ? 12 + (packetFactor) : 12);    
}

-(void)adjustRectSizeSize
{
    float sizeFactor = logf(size);
    sizeRect.size.width = (sizeFactor >= 1 ? 12 + (sizeFactor) : 12);
    sizeRect.size.height = (sizeFactor >= 1 ? 12 + (sizeFactor) : 12); 
}

-(void) addSize:(int)bytes
{
    size = size + bytes;
    //    size = (size > 10000000 ? 10000000 : size);
    [self adjustRectSizeSize];
}

- (void) reduceSize:(float)factor
{
    size = size * factor;
    if (size < 1) size = 1;
    [self adjustRectSizeSize];
}


-(void) addPacket
{
    packets = packets + 1;
    [self adjustRectSizePackets];
    [lastPacket release];
    lastPacket = [[NSDate alloc] init];
}

- (void) reducePackets:(float)factor
{
    packets = packets * factor;
    if (packets < 1) packets = 1;
    [self adjustRectSizePackets];
}
- (BOOL)isIP
{
    return IP;
}

- (void)setEthernet
{
    CGColorRef colorRef;
    ethernet = YES;
    CFRelease(color);
    if([address isEqualToString:@"ff:ff:ff:ff:ff:ff"])
    {
        colorRef = CGColorCreateGenericRGB(0.1, 0.9, 0.1, 1.0);
        color = colorRef;
        // CGColorRetain(color);
        return;
    }
    colorRef = CGColorCreateGenericRGB(0.1, 0.1, 0.9, 1.0);    
    color = colorRef;
    // CGColorRetain(color);
}

- (void)setIP
{
    CGColorRef colorRef;
    IP = YES;
    CFRelease(color);
    if([address isEqualToString:@"255.255.255.255"])
    {
        colorRef = CGColorCreateGenericRGB(0.9, 0.9, 0.1, 1.0);
        color = colorRef;
        // CGColorRetain(color);
        return;
    }
    if([address isEqualToString:@"169.254.255.255"])
    {
        colorRef = CGColorCreateGenericRGB(0.9, 0.4, 0.1, 1.0);
        color = colorRef;
        // CGColorRetain(color);
        return;
    }
    if([address isEqualToString:@"0.0.0.0"])
    {
        colorRef = CGColorCreateGenericRGB(0.9, 0.1, 0.9, 1.0);
        color = colorRef;
        // CGColorRetain(color);
        return;
    }
    if( [[[address componentsSeparatedByString:@"."] objectAtIndex:3] isEqualToString:@"255"])
    {
        colorRef = CGColorCreateGenericRGB(0.1, 0.9, 0.9, 1.0);
        color = colorRef;
        // CGColorRetain(color);
        return;
    }
    if( [[[address componentsSeparatedByString:@"."] objectAtIndex:0] intValue] >= 223
       && [[[address componentsSeparatedByString:@"."] objectAtIndex:0] intValue] < 240)
    {
        colorRef = CGColorCreateGenericRGB(0.3, 0.3, 0.3, 1.0);
        color = colorRef;
        return;
    }
    colorRef = CGColorCreateGenericRGB(0.9, 0.1, 0.1, 1.0);    
    color = colorRef;
    // CGColorRetain(color);
}

- (CGPoint) center
{
    return CGPointMake(xCenter, yCenter);
}

- (CGPoint) setCenterX:(int)x Y:(int)y
{
    xCenter = x;
    yCenter = y;
    return CGPointMake(xCenter, yCenter);
}

-(NSString *)description
{
    return [NSString stringWithFormat:@"Host: %@ is located at %f, %f", address, xCenter, yCenter];
}
@end
