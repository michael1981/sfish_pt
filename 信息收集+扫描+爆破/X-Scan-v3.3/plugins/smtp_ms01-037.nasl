#
# (C) Tenable Network Security, Inc.
#

# Thanks to Joao Gouveia

include( 'compat.inc' );

if(description)
{
  script_id(10703);
  script_version ("$Revision: 1.24 $");
  script_cve_id("CVE-2001-0504");
  script_bugtraq_id(2988);
  script_xref(name:"OSVDB", value:"581");

  script_name(english:"Microsoft Windows SMTP Incorrect Credentials Authentication Bypass");
  script_summary(english:"Checks if the remote mail server can be used as a spam relay");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote SMTP server is vulnerable to an authentication bypass.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote SMTP server is vulnerable to a flaw in its authentication
process.

This vulnerability allows any unauthorized user to successfully
authenticate and use the remote SMTP server.

An attacker may use this flaw to use this SMTP server
as a spam relay.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Apply the appropriate MS01-037 patches from Microsoft or upgrade to the latest service pack.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.microsoft.com/technet/security/bulletin/ms01-037.mspx'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
  script_family(english:"SMTP problems");
  script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
  script_exclude_keys("SMTP/wrapped", "SMTP/qmail", "SMTP/postfix");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 data = smtp_recv_banner(socket:soc);
 if(!data || !egrep(pattern:"^220.*", string:data))exit(0);

 cmd = string("HELO example.com\r\n");
 send(socket:soc, data:cmd);
 data = recv_line(socket:soc, length:1024);
 cmd = string("AUTH GSSAPI\r\n");
 send(socket:soc, data:cmd);
 r = recv_line(socket:soc, length:4096);

 if(ereg(string:r, pattern:"^334 .*"))
 {
  cmd = string(".\r\n");
  send(socket:soc, data:cmd);
  r = recv_line(socket:soc, length:4096);
  if(ereg(string:r, pattern:"^235 .*successful.*"))security_hole(port);
 }
 send(socket:soc, data:string("QUIT\r\n"));
 close(soc);
}
