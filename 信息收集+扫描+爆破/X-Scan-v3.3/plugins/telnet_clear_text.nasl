#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(42263);
 script_version ("$Revision: 1.1 $");

 script_name(english:"Unencrypted Telnet Server");
 script_summary(english:"Checks if telnet service is unencrypted");

 script_set_attribute(attribute:"synopsis", value:
"The remote Telnet server transmits traffic in cleartext." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Telnet server over an unencrypted
channel. 

Using Telnet over an unencrypted channel is not recommended as logins,
passwords and commands are transferred in cleartext.  An attacker may
eavesdrop on a Telnet session and obtain credentials or other
sensitive information. 

Use of SSH is prefered nowadays as it protects credentials from
eavesdropping and can tunnel additional data streams such as the X11
session." );
 script_set_attribute(attribute:"solution", value:
"Disable this service and use SSH instead." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/27");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/telnet", 23);
 
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item("Services/telnet");
if (!port) exit(0);

trp = get_port_transport(port);
if (trp > ENCAPS_IP) exit(0, "The Telnet service on port "+port+" encrypts traffic.");

soc = open_sock_tcp(port);
if (soc) security_note(port);
