//
//  VisualSniffAppDelegate.h
//  VisualSniff
//
//  Created by David Hoelzer on 10/1/11.
//  Copyright 2011 Enclave Forensics, Inc. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "Sniffer.h"
#import "Conversation.h"
#import "RawPacket.h"

@interface VisualSniffAppDelegate : NSObject <NSApplicationDelegate> {
    NSWindow *window;
    NSWindow *adapterSelectionWindow;
    NSWindow *settingsWindow;
    NSMutableArray *hosts;
    NSMutableArray *conversations;
    IBOutlet NSComboBox *interfaceSelection;
    IBOutlet NSButton *startButton;
    IBOutlet NSButton *drawSizes;
    IBOutlet NSButton *drawEthernetHosts;
    IBOutlet NSButton *drawIPV4Hosts;
    IBOutlet NSButton *openPcapFileButton;
    IBOutlet NSSlider *hostTimeout;
    IBOutlet NSTextField *timeoutLabel;
}

-(IBAction)closeSettings:(id)sender;
-(IBAction)triggerSettings:(id)sender;
-(int)hostTimeoutValue;
-(IBAction)adjustTimeout:(id)sender;
-(IBAction)openHelp:(id)sender;
-(IBAction)openPcapFile:(id)sender;
-(IBAction)startSniffer:(id)sender;
- (void) packetReceived:(NSNotification *)aNotice;
-(Host *)findOrAddHostForAddress:(NSString *)hostAddress withPacket:(RawPacket *)packet isSource:(Boolean)isSource type:(NSString *)type;
-(Conversation *)findOrAddConversationFrom:(Host *)source To:(Host *)destination withPacket:(RawPacket *)packet;
-(NSArray *)getConversationsReference;
-(NSArray *)getHostsReference;
-(Boolean)drawSizes;
-(Boolean)drawIPV4Hosts;
-(Boolean)drawEthernetHosts;

@property (assign) IBOutlet NSWindow *window;
@property (assign) IBOutlet NSWindow *settingsWindow;
@property (nonatomic, retain) IBOutlet NSTextField *timeoutLabel;
@property (nonatomic, retain, readwrite) IBOutlet NSComboBox *interfaceSelection;
@property (nonatomic, retain, readwrite) IBOutlet NSSlider *hostTimeout;

@end
