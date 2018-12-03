//
//  VisualSniffAppDelegate.m
//  VisualSniff
//
//  Created by David Hoelzer on 10/1/11.
//  Copyright 2011 Enclave Forensics, Inc. All rights reserved.
//

#import "VisualSniffAppDelegate.h"
#import "Host.h"
#import "RawPacket.h"
#import "Conversation.h"
#import "Map.h"
#import "pcap.h"


@implementation VisualSniffAppDelegate
{

}

@synthesize window, interfaceSelection, hostTimeout, timeoutLabel, settingsWindow;

- (id)init
{
    self = [super init];
    if(self)
    {
        hosts = [[NSMutableArray alloc] init];
        conversations = [[NSMutableArray alloc] init];
    }
    return self;
}

-(IBAction)adjustTimeout:(id)sender
{
    [timeoutLabel setIntValue:[self hostTimeoutValue]];
}

-(void)removeUnecessaryInterfaceItems
{
    [interfaceSelection setEnabled:NO];
    [interfaceSelection removeFromSuperview];
    [startButton removeFromSuperview];
    [openPcapFileButton removeFromSuperview];    
}

-(void)startMap
{
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(packetReceived:) name:@"packetReceived" object:nil];
    [NSTimer scheduledTimerWithTimeInterval:0.05 target:self selector:@selector(updatePackets) userInfo:nil repeats:YES];
    Map *map = [[Map alloc] initWithFrame:[[window contentView] bounds]];
    [map setConversationDelegate:self];
    [[window contentView] addSubview:map];
    [map setNeedsDisplay:YES];
    [map release];   
}

-(IBAction)openPcapFile:(id)sender
{
    Sniffer *theSniffer;
 	NSOpenPanel *panel = [NSOpenPanel openPanel];
    NSString *theFileName;
	
	[panel setTitle:@"Select PCap File"];
    [panel setPrompt: @"Open Packet Capture"];
	
	NSInteger result=[panel runModal];
	if(result == NSOKButton)
	{
        theFileName = [[panel URLs] objectAtIndex:0];
        NSLog(@"%@ selected", theFileName);
	}
    else return;
    theSniffer = [[Sniffer alloc] initWithFile:theFileName];
    if (!theSniffer) {

            NSAlert *alertBox = [[NSAlert alloc] init];
            [alertBox setAlertStyle:NSInformationalAlertStyle];
            [alertBox setMessageText:@"Invalid File"];
            [alertBox setInformativeText:@"The file that you selected could not be opened or is not a packet capture!"];
            [alertBox addButtonWithTitle:@"OK"];
            [alertBox runModal];
            [alertBox release];
            return;


    }
    [self removeUnecessaryInterfaceItems];
    [self startMap];
}

-(int)hostTimeoutValue
{
    int value = (int)[hostTimeout integerValue];
    value = ( value < 1 ? 1 : value);
    value = value * 5;
    return value;
}

-(IBAction)openHelp:(id)sender
{
    NSURL *helpURL = [[NSURL alloc] initWithString:@"http://enclaveforensics.com/page5/VisualSniff.html"];
    [[NSWorkspace sharedWorkspace] openURL:helpURL];
    [helpURL release];
}

-(IBAction)startSniffer:(id)sender
{
    Sniffer *theSniffer;
    if([[interfaceSelection stringValue] isEqualToString:@""])
    {
        NSAlert *alertBox = [[NSAlert alloc] init];
        [alertBox setAlertStyle:NSInformationalAlertStyle];
        [alertBox setMessageText:@"No interface selected."];
        [alertBox setInformativeText:@"You must first select an interface from the drop-down box before you can start the sniffer!"];
        [alertBox addButtonWithTitle:@"OK"];
        [alertBox runModal];
        [alertBox release];
        return;
    }
    theSniffer = [[Sniffer alloc] initWithDevice:[interfaceSelection stringValue]];
    [self removeUnecessaryInterfaceItems];
    [self startMap];
}

-(Boolean)drawSizes
{
    return [drawSizes state];
}

-(Boolean)drawEthernetHosts
{
    return [drawEthernetHosts state];
}

-(Boolean)drawIPV4Hosts
{
    return [drawIPV4Hosts state];
}

-(IBAction)closeSettings:(id)sender
{
    [NSApp endSheet:settingsWindow];
    [settingsWindow orderOut:sender];
}

-(IBAction)triggerSettings:(id)sender
{
    NSLog(@"Trigger Settings");
    [NSApp beginSheet:settingsWindow modalForWindow:window modalDelegate:nil didEndSelector:NULL contextInfo:NULL];
}

- (void)awakeFromNib
{
    pcap_if_t *allInterfaces, *currentInterface;
    char errbuf[4096];
    
    NSMutableArray *interfaces = [[NSMutableArray alloc] init];
    pcap_findalldevs(&allInterfaces, errbuf);
    currentInterface = allInterfaces;
    while (currentInterface) {
        [interfaces addObject:[NSString stringWithFormat:@"%s", currentInterface->name]];
        currentInterface = currentInterface->next;
    }
    [interfaceSelection setNumberOfVisibleItems:[interfaces count]];
    [interfaceSelection addItemsWithObjectValues:interfaces];
    if([interfaces count] < 1) {
        [startButton setEnabled:NO];
        [interfaceSelection setEnabled:NO];
    }
    [hostTimeout setIntValue:7];
    [self adjustTimeout:nil];
    [interfaces release];
}

-(NSArray *)getConversationsReference
{
    return conversations;
}

-(NSArray *)getHostsReference
{
    return hosts;
}

- (void) packetReceived:(NSNotification *)aNotice
{
    Host *ehSource, *ehDest;
    Host *ipSource, *ipDest;
    RawPacket *currentPacket = [[aNotice object] retain];
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    
    ehSource = [self findOrAddHostForAddress:[currentPacket getEtherSourceHost] withPacket:currentPacket isSource:YES type:@"Ethernet"];
    ehDest = [self findOrAddHostForAddress:[currentPacket getEtherDestinationHost] withPacket:currentPacket isSource:NO type:@"Ethernet"];
    [self findOrAddConversationFrom:ehSource To:ehDest withPacket:currentPacket];    
    if ([currentPacket isIP])
    {
        ipSource = [self findOrAddHostForAddress:[currentPacket getIPSourceHost] withPacket:currentPacket isSource:YES type:@"IPV4"];
        ipDest = [self findOrAddHostForAddress:[currentPacket getIPDestinationHost] withPacket:currentPacket isSource:NO type:@"IPV4"];
        [self findOrAddConversationFrom:ipSource To:ipDest withPacket:currentPacket];
    }
    

    [currentPacket release];
    [pool drain];
}


-(Conversation *)findOrAddConversationFrom:(Host *)source To:(Host *)destination withPacket:(RawPacket *)packet
{
    NSString *signature = [NSString stringWithFormat:@"%@->%@", [source address], [destination address]];
    Conversation *conversation;
    
    
    for (conversation in conversations)
    {
        if([[conversation idTag] isEqualToString:signature])
        {
            [conversation addPacket];
            [conversation addSize:[packet packetSize]];
            return conversation;
        }
    }
    conversation = [[Conversation alloc] init];
    [conversation setSourceHost:source];
    [conversation setDestinationHost:destination];
    [conversation setIdTag:signature];
    [conversation addPacket];
    [conversation addSize:[packet packetSize]];
    [conversation reducePackets:25];
    [conversations addObject:conversation];
    return conversation;
}

-(Host *)findOrAddHostForAddress:(NSString *)hostAddress withPacket:(RawPacket *)packet isSource:(Boolean)isSource type:(NSString *)type
{
    Host *thisHost;
    BOOL found=NO;
    
    for (Host *host in hosts)
    {
        if([hostAddress isEqualToString:host.address])
        {
            thisHost = host;
            found = true;
            break;
        }
    }
    if (!found){
        thisHost = [[[Host alloc]initWithAddress:hostAddress] autorelease];
        if([type isEqualToString:@"Ethernet"]) [thisHost setEthernet];
        if([type isEqualToString:@"IPV4"]) [thisHost setIP];
        [hosts addObject:thisHost];
    }
    [thisHost addPacket];
    if(isSource) [thisHost addSize:[packet packetSize]];
    
    return thisHost;
}

-(void)updatePackets
{
    for (Conversation *conv in conversations)
    {
        [conv reducePackets:0.98];
        [conv reduceSize:0.98];
    }
    for (Host *host in hosts)
    {
        [host reducePackets:0.99];
        [host reduceSize:0.99];
    }
    [[window contentView] setNeedsDisplay:YES];
}

- (void) dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [super dealloc];
}
@end
