#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(26925);
 script_version("$Revision: 1.4 $");

 script_name(english:"VNC Server Unauthenticated Access");
 script_summary(english:"Tries to authenticate using a type of None");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote VNC server does not require authentication." );
 script_set_attribute(attribute:"description", value:
"The VNC server installed on the remote host allows an attacker
to connect to the remote host as no authentication is required
to access this service." );
 script_set_attribute(attribute:"solution", value:
"Disable the No Authentication security type." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_dependencies("vnc_security_types.nasl");
 script_require_ports("Services/vnc", 5900);

 exit(0);
}

port = get_kb_item("VNC/SecurityNoAuthentication");
if (!isnull(port))
  security_hole(port);

