#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# References:
# Date:  Tue, 3 Jul 2001 19:05:10 +0200 (CEST)
# From: "Andrea Barisani" <lcars@infis.univ.trieste.it>
# To: bugtraq@securityfocus.com
# Subject: poprelayd and sendmail relay authentication problem (Cobalt Raq3)
#


include("compat.inc");

if(description)
{
 script_id(11080);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2001-1075");
 script_bugtraq_id(2986);
 script_xref(name:"OSVDB", value:"1893");

 script_name(english: "poprelayd & sendmail Arbitrary Mail Relay");
 
  script_set_attribute(attribute:"synopsis", value:
"An open SMTP relay may be running on this port." );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server allows relaying for users which were identified
by 'POP before SMTP'.
The access control mechanism is based upon the POP server logs. It is 
however possible to poison these logs; this means that spammers would be
able to use your server to send their e-mails to the world, thus wasting
your network bandwidth and getting you blacklisted.

*** Some SMTP servers such as Postfix will display a false positive
*** here." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-07/0064.html" );
 script_set_attribute(attribute:"solution", value:
"Disable poprelayd or upgrade it" );

script_end_attributes();

		    
 script_summary(english: "Checks if the remote mail server can be used as a spam relay");
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc."); 
 script_family(english: "SMTP problems");
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl", 
		"smtp_relay.nasl", "smtp_settings.nasl");
 script_exclude_keys("SMTP/wrapped", "SMTP/postfix", "SMTP/qmail");
 script_require_ports("Services/smtp", 25);
 exit(0);
}


include("smtp_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

# can't perform this test on localhost
if(islocalhost())exit(0);

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

data = smtp_recv_banner(socket:soc);
if(!data)exit(0);

domain = get_kb_item("Settings/third_party_domain");
 
hel = string("HELO ", domain, "\r\n");
send(socket:soc, data:hel);
data = recv_line(socket:soc, length:1024);
mf1 = string("MAIL FROM: <test_1@", domain, ">\r\n");
send(socket:soc, data:mf1);
data = recv_line(socket:soc, length:1024);
rc1 = string("RCPT TO: <test_2@", domain, ">\r\n");
send(socket:soc, data: rc1);
data = recv_line(socket:soc, length:1024);
if ("Relaying denied. Please check your mail first." >< data) { suspicious=1;}
else if(ereg(pattern:"^250 .*", string:data))exit(0);

q = raw_string(0x22);	# Double quote
h = this_host();
mf = string("mail from:", q, "POP login by user ", q, "admin", q,
	" at (", h, ") ", h, "@example.org\r\n");
send(socket: soc, data: mf);
data = recv_line(socket:soc, length:1024);
close(soc);
#
#sleep(10);
#
soc = open_sock_tcp(port);
if (!soc) exit(0);

data = smtp_recv_banner(socket:soc);
send(socket:soc, data:hel);
data = recv_line(socket:soc, length:1024);
send(socket:soc, data:mf1);
data = recv_line(socket:soc, length:1024);
send(socket:soc, data: rc1);
i = recv_line(socket:soc, length:4);
if (i == "250 ") security_warning(port);
close(soc);
