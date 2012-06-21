//
//  CViewController.m
//  iOS_Pop3_Smtp
//
//  Created by S on 6/21/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import "CViewController.h"

#include <string>
#include <iostream>
#include <Mac/CFSocketByteStream.h>
#include <Pop3.h>
#include <Smtp.h>

@interface CViewController ()

@end

@implementation CViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
}

- (void)viewDidUnload
{
    [super viewDidUnload];
    // Release any retained subviews of the main view.
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPhone) {
        return (interfaceOrientation != UIInterfaceOrientationPortraitUpsideDown);
    } else {
        return YES;
    }
}

- (IBAction)OnDoPop3 {
	const std::string    Pop3Server = "pop.gmail.com";
	const bool           UseSSL     = true;
	const unsigned short Pop3Port   = UseSSL ? 995 : 110;
    
	const std::string    Pop3User   = "vasya.pupkin@gmail.com";
	const std::string    Pop3Pass   = "password";
    
    CFSocketByteStream ss;
    if( ss.Open( Pop3Server.c_str(), Pop3Port, UseSSL) ) {    
        
		std::cout<<"Connected to: "<<Pop3Server<<" port:"<<Pop3Port<<std::endl;
        
		try{
			//POP3 protocol conversation
			LPop3 pop3( &ss );
			pop3.Greeting();
			std::cout<<"Server greeting: "<<pop3.GetResponse();
            
			if( pop3.USER(Pop3User) && pop3.PASS(Pop3Pass) ) {
				std::cout<<"User name: "<<Pop3User<<std::endl;
                
				unsigned int MessagesCount;
				pop3.STAT(&MessagesCount);
                
				std::cout<<"Total messages: "<<MessagesCount<<std::endl<<std::endl;
				std::vector<char> msg_body;
				for( unsigned int i=1; i<MessagesCount+1; ++i) {
					pop3.TOP(i, 0, &msg_body);
					msg_body.push_back('\0');
					std::cout<<"Message #"<<i<<" headers:"<<std::endl;
					std::cout<<&msg_body[0];
				}
			}
            
			pop3.QUIT();
		}
		catch(LPop3::BAD_POP3_PROTOCOL&){//some problem with POP3
			return;
		}
		catch(LBS_EOF&){//connection closed.
			return;
		}
		catch(CFS_IO_ERROR&){//some problems with CFSocket.
			return;
		}
		catch(int){//some problem with socket io.
			return;
		}
	}
}

- (IBAction)OnDoSMTP {
	const std::string    SMTPServer = "smtp.gmail.com";
	const bool           UseSSL     = true;
	const unsigned short SMTPPort   = UseSSL ? 465 : 25;
    
	const std::string    SMTPUser   = "vasya.pupkin@gmail.com";
	const std::string    SMTPPass   = "password";
	const std::string    SMTPFrom   = SMTPUser;
	const std::string    SMTPTo     = SMTPUser;
    
    CFSocketByteStream ss;
    if( ss.Open( SMTPServer.c_str(), SMTPPort, UseSSL) ) {    
		std::cout<<"Connected to: "<<SMTPServer<<" port:"<<SMTPPort<<std::endl;
        
		try{
			//SMTP protocol conversation
			LSmtp smtp( &ss );
			smtp.Greeting();
			std::cout<<"Server greeting: "<<smtp.GetReply();
			std::vector<std::string> Extensions;
			smtp.EHLO("anonymous", &Extensions);
			if( smtp.AUTH_PLAIN(std::string(), SMTPUser, SMTPPass) ) {
				std::cout<<"User name: "<<SMTPUser<<std::endl;
				std::cout<<std::endl;
                
				std::string Message;
				Message += "from: "+SMTPFrom+"\r\n";
				Message += "to:"+SMTPTo+"\r\n";
				Message += "subject: Hello world!\r\n";
				Message += "\r\n";
				Message += "It works!.\r\n";
				Message += ".\r\n";
				std::cout<<"Trying to send message: "<<std::endl;
				std::cout<<std::endl<<Message<<std::endl;
                
				if( smtp.MAIL(SMTPFrom)&&
                   smtp.RCPT(SMTPTo)&&
                   smtp.DATA(&Message[0], Message.size()) )
				{
					std::cout<<"Success!"<<std::endl;
				} else {
					std::cout<<"Failed!"<<std::endl;
				}
			}
			smtp.QUIT();
		}
		catch(LSmtp::BAD_SMTP_PROTOCOL&){//some problem with SMTP
			return;
		}
		catch(LBS_EOF&){//connection closed.
			return;
		}
		catch(CFS_IO_ERROR&){//some problems with CFSocket.
			return;
		}
	}
}
@end
