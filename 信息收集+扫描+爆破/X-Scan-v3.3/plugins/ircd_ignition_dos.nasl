#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14376);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(11041);
 script_xref(name:"OSVDB", value:"9166");
 
 script_name(english:"ignitionServer SERVER Command Spoofed Server Saturation DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IRC server is affected by a denial of service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the IgnitionServer IRC 
service which may be vulnerable to a denial of service in the SERVER
command.

An attacker may crash the remote host by misusing the SERVER command
repeatdly." );
 script_set_attribute(attribute:"see_also", value:"http://www.ignition-project.com/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IgnitionServer 0.3.2 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"checks the version of the remote ircd");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl", "find_service2.nasl", "ircd.nasl");
 script_require_ports("Services/irc", 6667);
 exit(0);
}

#

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(! get_port_state(port)) exit(0);

key = string("irc/banner/", port);
banner = get_kb_item(key);
if(!banner)exit(0);

if(egrep(pattern:".*ignitionServer 0\.([0-2]\.|3\.[01][^0-9]).*", string:banner)) 
{
 security_warning(port);
 exit(0);
}

