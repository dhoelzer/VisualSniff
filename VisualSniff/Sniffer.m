//
//  Sniffer.m
//  VisualSniff
//
//  Created by David Hoelzer on 10/1/11.
//  Copyright 2011 Enclave Forensics, Inc. All rights reserved.
//

#import "Sniffer.h"
#include "pcap.h"
#import "RawPacket.h"

@implementation Sniffer
{

    
}
struct timeval starting_timestamp;
struct timeval last_timestamp;
NSDate *startingTime;
    id CRefToSelf;
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

- (id)initWithDevice:(NSString *)deviceName
{
    self = [super init];
    if (self) {
        deviceString = deviceName;
        [deviceString retain];
    }
    CRefToSelf = self;
    [self startSniffer];
    return self;
}

- (id)initWithFile:(NSString *)fileName
{
    self = [super init];
    if (!self) {
        return self;
    }
    CRefToSelf = self;
    if (![self startOffline:fileName])
    {
        [self autorelease];
        return nil;
    };
    return self;
}

-(void)processPacket:(const u_char *)packet length:(int)packetLength
{
    RawPacket *receivedPacket = [[[RawPacket alloc] initWithPacket:packet length:packetLength] autorelease];
    [[NSNotificationCenter defaultCenter] postNotification:[NSNotification notificationWithName:@"packetReceived" object:receivedPacket]];
}



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    [CRefToSelf processPacket:packet length:header->len];
    
}

void got_offline_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    if(startingTime == nil)
    {
        startingTime = [[NSDate alloc] init];
        last_timestamp.tv_sec = 0;
        last_timestamp.tv_usec = 0;
        starting_timestamp.tv_sec = header -> ts.tv_sec;
        starting_timestamp.tv_usec = header -> ts.tv_usec;
        
    }
    while((header->ts.tv_sec - starting_timestamp.tv_sec) > last_timestamp.tv_sec)
    {
        last_timestamp.tv_sec = abs([startingTime timeIntervalSinceNow]);
    }
    [CRefToSelf processPacket:packet length:header->len];
    
}

- (void)startOfflineCapture:(NSURL *)fileName
{
    char error_buffer[4096];
    const char *theFileName;

    theFileName = [[fileName relativePath] UTF8String];
    NSLog(@"Starting with %s", theFileName);
    listener = pcap_open_offline(theFileName, error_buffer);
    NSLog(@"%s", error_buffer);
    if(!listener) return;
    pcap_loop(listener, -1, got_offline_packet, NULL);
    
}

- (void)startCapture:(NSString *)sniffDev {
    char error_buffer[4096];

    device = [sniffDev UTF8String];
    listener = pcap_open_live(device, 100, 1, 50, error_buffer);
    pcap_loop(listener, -1, got_offline_packet, NULL);
    
}


- (void)startSniffer
{

    parentSniffer = self;
    
    [NSThread detachNewThreadSelector:@selector(startCapture:)
                             toTarget:self
                           withObject:deviceString];

    
}

- (Boolean)startOffline:(NSURL *)fileName
{
    char error_buffer[4096];
    const char *theFileName;
    pcap_t *test_listener;
    
    theFileName = [[fileName relativePath] UTF8String];
    NSLog(@"Starting with %s", theFileName);
    test_listener = pcap_open_offline(theFileName, error_buffer);
    NSLog(@"%s", error_buffer);

    if(!test_listener) return NO;

    parentSniffer = self;
    
    [NSThread detachNewThreadSelector:@selector(startOfflineCapture:)
                             toTarget:self
                           withObject:fileName];
    return YES;
    
    
}


@end
