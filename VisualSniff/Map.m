//
//  Map.m
//  VisualSniff
//
//  Created by David Hoelzer on 10/15/11.
//  Copyright 2011 Enclave Forensics, Inc. All rights reserved.
//

#import "Map.h"
#import "Conversation.h"
#import "VisualSniffAppDelegate.h"

@implementation Map
{
}

@synthesize doShowHosts;

struct CGColor *aRedColor;
struct CGColor *aBlueColor;

- (id)initWithFrame:(NSRect)frame
{
    CGColorRef colorRef;
    self = [super initWithFrame:frame];
    if (self) {
        doShowHosts = YES;
        radialOffset = 0;
        colorRef = CGColorCreateGenericRGB(0.9, 0.1, 0.1, 1.0);
        aRedColor = colorRef;
        // CGColorRetain(redColor);
        colorRef = CGColorCreateGenericRGB(0.1, 0.1, 0.9, 1.0);
        aBlueColor = colorRef;
        // CGColorRetain(blueColor);
    }
    
    return self;
}

-(void)dealloc
{
    CFRelease(aRedColor);
    CFRelease(aBlueColor);
    [super dealloc];
}

-(void)awakeFromNib
{
}

-(void)setConversationDelegate:(id)object
{
    conversationDelegate = object;
}

-(void) drawHosts
{
    int hidden_after = [conversationDelegate hostTimeoutValue];
    Boolean drawSizes = [conversationDelegate drawSizes];
    NSPredicate *ethernetPredicate = [NSPredicate predicateWithFormat:[NSString stringWithFormat:@"ethernet == YES AND lastPacketReceived < %d", hidden_after]];
    NSPredicate *IPPredicate = [NSPredicate predicateWithFormat:[NSString stringWithFormat:@"IP == YES AND lastPacketReceived < %d", hidden_after]];
    Boolean drawEthernetHosts = [conversationDelegate drawEthernetHosts];
    Boolean drawIPV4Hosts = [conversationDelegate drawIPV4Hosts];
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    
    NSArray *ethernetHosts = [[[NSArray alloc] initWithArray:[hosts filteredArrayUsingPredicate:ethernetPredicate]] autorelease]; 
    NSArray *IPHosts = [[[NSArray alloc] initWithArray:[hosts filteredArrayUsingPredicate:IPPredicate]] autorelease];
    
    
    unsigned long numEtherHosts = [ethernetHosts count];
    unsigned long numIPHosts = [IPHosts count];
    double angularSeparation = 0.0;
    double smallestDimension = 0;
    double radius, maxRadius;
    double transX, transY;

    NSRect viewFrame = [self bounds];

    smallestDimension = (viewFrame.size.width > viewFrame.size.height ? viewFrame.size.height : viewFrame.size.width);
    maxRadius = (smallestDimension / 2);
    

    CGPoint centerPoint = CGPointMake((viewFrame.size.width / 2), (viewFrame.size.height / 2));
    CGPoint newLocation;
    
    angularSeparation = (2 * 3.14157911) / numEtherHosts;
    radius = maxRadius * 0.75; // Radius for Ethernet hosts
    CGContextSetLineWidth(context, 1);
    float x = 0 - radialOffset;
    if(drawEthernetHosts){
        for (Host *host in ethernetHosts)
        {
            transX = radius * cos(x);
            transY = radius * sin(x);
            newLocation = CGPointMake(transX + centerPoint.x, transY + centerPoint.y);
            [host moveTo:newLocation];
            CGContextSetFillColorWithColor(context, [host color]);
            if(drawSizes){
                CGContextFillEllipseInRect(context, [host sizeRect]);
            }
            else
            {
                CGContextFillEllipseInRect(context, [host packetRect]);
            }
            x = x + angularSeparation;
            if(doShowHosts)
            {
                CGContextSaveGState(context);
                newLocation.x = newLocation.x + 15;
                newLocation.y = newLocation.y - 7.5;
                [[host address] drawAtPoint:NSPointFromCGPoint(newLocation) withAttributes:nil];
                CGContextRestoreGState(context);
            }
            else if (host == pointedHost)
            {
                CGContextSaveGState(context);
                newLocation.x = newLocation.x + 15;
                newLocation.y = newLocation.y - 15;
                [[host address] drawAtPoint:NSPointFromCGPoint(newLocation) withAttributes:nil];
                CGContextRestoreGState(context);
                
            }
        }
    }
    
    angularSeparation = (2 * 3.14157911) / numIPHosts;
    radius = maxRadius * 0.95; // Radius for IP hosts
    x = 0 + radialOffset;
    if(drawIPV4Hosts) {
        for (Host *host in IPHosts)
        {
            transX = radius * cos(x);
            transY = radius * sin(x);
            x = x + angularSeparation;
            newLocation = CGPointMake(transX + centerPoint.x, transY + centerPoint.y);
            [host moveTo:newLocation];
            CGContextSetFillColorWithColor(context, [host color]);
            if(drawSizes)
            {
                CGContextFillEllipseInRect(context, [host sizeRect]);
            }
            else
            {
                CGContextFillEllipseInRect(context, [host packetRect]);
            }
            if(doShowHosts)
            {
                CGContextSaveGState(context);
                newLocation.x = newLocation.x + 15;
                newLocation.y = newLocation.y - 7.5;
                [[host address] drawAtPoint:NSPointFromCGPoint(newLocation) withAttributes:nil];
                CGContextRestoreGState(context);
            }
            else if (host == pointedHost)
            {
                CGContextSaveGState(context);
                newLocation.x = newLocation.x + 15;
                newLocation.y = newLocation.y - 15;
                [[host address] drawAtPoint:NSPointFromCGPoint(newLocation) withAttributes:nil];
                CGContextRestoreGState(context);
                
            }
            
        }
    }
    [pool drain];
}

- (void)drawRect:(NSRect)dirtyRect
{
    Boolean drawSizes = [conversationDelegate drawSizes];
    Boolean drawEthernetHosts = [conversationDelegate drawEthernetHosts];
    Boolean drawIPV4Hosts = [conversationDelegate drawIPV4Hosts];
    
    context = (CGContextRef)[[NSGraphicsContext currentContext] graphicsPort];
    [self setFrame:[[[self window] contentView] bounds]];
    
    conversations = [[NSArray alloc] initWithArray:[(VisualSniffAppDelegate *)conversationDelegate getConversationsReference]];
    int hidden_after = [conversationDelegate hostTimeoutValue];
    NSPredicate *conversationsPredicate = [NSPredicate predicateWithFormat:[NSString stringWithFormat:@"lastPacketReceived < %d", hidden_after]];
    NSArray *conversationsFiltered = [[NSArray alloc] initWithArray:[conversations filteredArrayUsingPredicate:conversationsPredicate]]; 
    
    hosts = [[NSArray alloc]initWithArray:[(VisualSniffAppDelegate *)conversationDelegate getHostsReference]];

    for (Conversation *conversation in conversationsFiltered)
    {
        Host *source, *dest;
        NSBezierPath *conversationPath;
        
        if((drawIPV4Hosts && [[conversation sourceHost] isIP]) || (drawEthernetHosts && [[conversation sourceHost] isEthernet]))
        {
            source = conversation.sourceHost;
            dest = conversation.destinationHost;
            if (source.center.x < 1 || source.center.y < 1 || dest.center.x < 1 || dest.center.y < 1)
            {
                continue;
            }
            conversationPath = [NSBezierPath bezierPath];
            if(drawSizes)
            {
                [conversationPath moveToPoint:NSMakePoint(source.center.x, source.center.y)];
                [conversationPath lineToPoint:NSMakePoint(source.center.x - ([conversation adjustedSize]), 
                                                          source.center.y - ([conversation adjustedSize]))];
                [conversationPath lineToPoint:NSMakePoint(dest.center.x, dest.center.y)];
                [conversationPath lineToPoint:NSMakePoint(source.center.x + ([conversation adjustedSize]), 
                                                          source.center.y + ([conversation adjustedSize]))];
                [conversationPath lineToPoint:NSMakePoint(source.center.x, source.center.y)];
            }
            else
            {
                [conversationPath moveToPoint:NSMakePoint(source.center.x, source.center.y)];
                [conversationPath lineToPoint:NSMakePoint(source.center.x - ([conversation adjustedPackets]), 
                                                          source.center.y - ([conversation adjustedPackets]))];
                [conversationPath lineToPoint:NSMakePoint(dest.center.x, dest.center.y)];
                [conversationPath lineToPoint:NSMakePoint(source.center.x + ([conversation adjustedPackets]), 
                                                          source.center.y + ([conversation adjustedPackets]))];
                [conversationPath lineToPoint:NSMakePoint(source.center.x, source.center.y)];
                
            }
            [[NSColor blueColor] setFill];
            [conversationPath fill];
        }
    }
    
    [self drawHosts];
    radialOffset = radialOffset + 0.0015;
    [hosts release];
    [conversations release];
    [conversationsFiltered release];
}

@end
