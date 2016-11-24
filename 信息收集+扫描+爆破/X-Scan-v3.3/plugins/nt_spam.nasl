#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10167);
 script_version ("$Revision: 1.34 $");
 script_cve_id("CVE-1999-0819");
 script_xref(name:"OSVDB", value:"130");
 script_name(english:"NTMail3 Arbitrary Mail Relay");
 
 script_set_attribute(attribute:"synopsis", value:
"An open SMTP relay is running on this port." );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server allows anyone to use it as a mail relay, provided
that the source address is set to '<>'. 
This problem allows any spammer to use your mail server to send their 
mails to the world, thus wasting your network bandwidth and possibly
getting your mailserver blacklisted.");
 script_set_attribute(attribute:"solution", value:
"Reconfigure your SMTP server so that it cannot be used as a relay 
any more.");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
  script_end_attributes();

 script_summary(english:"Checks if the remote mail server can be used as a spam relay"); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("find_service1.nasl", "smtp_relay.nasl", "sendmail_expn.nasl", "smtp_settings.nasl");
 script_exclude_keys("SMTP/fake", "SMTP/spam", "SMTP/qmail", "SMTP/postfix");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("smtp_func.inc");
include("network_func.inc");

if(islocalhost())exit(0);
if (is_private_addr()) exit(0);

port = get_kb_item("Services/smtp");
if(!port)port = 25;

# Don't give the information twice
if (get_kb_item("SMTP/" + port + "/spam")) exit(0);

if (!get_port_state(port)) exit(0);

 domain = get_kb_item("Settings/third_party_domain");
 
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 
 data = smtp_recv_banner(socket:soc);
 if(!data)exit(0);
 if(!ereg(pattern:"^220 ", string:data))exit(0);
 
 crp = string("HELO ", domain, "\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!ereg(pattern:"^250 ", string:data))exit(0);
 
send(socket:soc, data: 'MAIL FROM:<>\r\n');
 data = recv_line(socket:soc, length:1024);
 if(!ereg(pattern:"^250 ", string:data))exit(0);
 crp = string("RCPT TO: nobody@", domain, "\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(ereg(pattern:"^250 ", string:data)){
 	send(socket:soc, data:'DATA\r\n');
	data = recv_line(socket:soc, length:1024);
	if(ereg(pattern:"^[2-3][0-9][0-9] .*", string:data))security_hole(port);
	}
 close(soc);

