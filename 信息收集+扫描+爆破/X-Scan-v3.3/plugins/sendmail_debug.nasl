#
# (C) Tenable Network Security, Inc.
#

# MA 2004-12-29: I merge sendmail_wiz.nasl into this one

include("compat.inc");

if(description)
{
 script_id(10247);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-1999-0095", "CVE-1999-0145");
 script_bugtraq_id(1, 2897);
 script_xref(name:"OSVDB", value:"195");
 script_xref(name:"OSVDB", value:"15962");

 script_name(english: "Sendmail DEBUG/WIZ Remote Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run on this server." );
 script_set_attribute(attribute:"description", value:
"Your MTA accepts the DEBUG or WIZ command. It must be a very old version
of sendmail.

This command is dangerous as it allows remote users to execute arbitrary
commands as root without the need to log in." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your MTA." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english: "Checks for the presence of DEBUG or WIZ commands");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english: "SMTP problems");
 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl", "smtpscan.nasl");
 script_require_keys("SMTP/sendmail");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(!get_port_state(port))exit(0);

if (get_kb_item('SMTP/'+port+'/broken')) exit(0);
if (! get_kb_item("SMTP/sendmail")) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

b = smtp_recv_banner(socket:soc);
if (!b)
{
  close(soc);
  exit(0);
}


foreach cmd (make_list('DEBUG', 'WIZ'))
{
  send(socket:soc, data: cmd + '\r\n');
  r = recv_line(socket:soc, length:1024);
  if (r =~ '^2[0-9][0-9][ \t]')
  {
   security_hole(port: port, extra: "The remote MTA accepts the "+cmd+" command.");
   break;
  }
}
close(soc);

