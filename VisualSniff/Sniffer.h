//
//  Sniffer.h
//  VisualSniff
//
//  Created by David Hoelzer on 10/1/11.
//  Copyright 2011 Enclave Forensics, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "pcap.h"
#import "Host.h"

@interface Sniffer : NSObject
{
    const char *device;
    NSString *deviceString;
    pcap_t *listener;
    bool isSniffing;
    id startButton;
    Sniffer *parentSniffer;

}
- (void)startSniffer;
- (Boolean)startOffline:(NSString *)fileName;
- (void)startOfflineCapture:(NSString *)fileName;
- (id)initWithDevice:(NSString *)deviceName;
- (id)initWithFile:(NSString *)fileName;
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void got_offline_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
@end
