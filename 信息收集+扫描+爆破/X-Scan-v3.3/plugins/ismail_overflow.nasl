#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Message-ID: <000001c2deba$8928f000$0200a8c0@r00t3d.net>
# Date: Thu, 27 Feb 2003 15:45:17 -0800
# From: "NGSSoftware Insight Security Research" <mark@ngssoftware.com>
# To: <bugtraq@securityfocus.com>, <ntbugtraq@listserv.ntbugtraq.com>,
#        <vulnwatch@vulnwatch.org>
# Subject: [VulnWatch] ISMAIL (All Versions) Remote Buffer Overrun
#


include("compat.inc");

if(description)
{
 script_id(11272);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2003-1382");
 script_bugtraq_id(6972); 
 script_xref(name:"OSVDB", value:"51820");

 script_name(english:"ISMail Multiple Command Domain Name Handling Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server (probably ISMail) seems to be vulnerable to a 
buffer overflow which could allow an attacker to gain LOCALSYSTEM 
privileges on this host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2003/q1/0097.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.4.5 of ISMail" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks if the remote mail server can be used to gain a shell"); 
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 
 script_family(english:"SMTP problems");
 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl");
 script_exclude_keys("SMTP/wrapped", 
 		     "SMTP/microsoft_esmtp_5", 
		     "SMTP/qmail", 
		     "SMTP/postfix");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(!get_port_state(port))exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
banner = smtp_recv_banner(socket:soc);
send(socket:soc, data:string("HELP\r\n"));
r = smtp_recv_line(socket:soc);

# The typo is _normal_, this is how we recognize ISMail
if("502 Command not implmented" >< r)
{
send(socket:soc, data:string("HELO example.com\r\n"));
r = smtp_recv_line(socket:soc);

# This is not a buffer overflow. I doubt anything would crash on that.
send(socket:soc, data:string("MAIL FROM: <nessus@", crap(255), ".org>\r\n"));
r = smtp_recv_line(socket:soc);

# Patched version should send an error for such a long domain
if(egrep(pattern:"^250 Action.*", string:r))security_hole(port);
send(socket:soc, data:string("QUIT\r\n"));
close(soc);
}
