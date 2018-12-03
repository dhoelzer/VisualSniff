//
//  Map.h
//  VisualSniff
//
//  Created by David Hoelzer on 10/15/11.
//  Copyright 2011 Enclave Forensics, Inc. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "Host.h"

@interface Map : NSView
{
    id conversationDelegate;
    NSArray *hosts, *conversations;
    Host *pointedHost;
    CGContextRef context;
    float radialOffset;
    BOOL doShowHosts;

}

@property BOOL doShowHosts;
-(void)setConversationDelegate:(id)object;
@end
