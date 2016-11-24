#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20870);
  script_version("$Revision: 1.8 $");

  script_name(english:"LDAP Server Detection");
  script_summary(english:"Detects an LDAP server");

 script_set_attribute(attribute:"synopsis", value:
"There is an LDAP server active on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Lightweight Directory Access Protocol, or
LDAP, server.  LDAP is a protocol for providing access to directory
services over TCP/IP." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/LDAP" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 389);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) 
{
  port = get_unknown_svc(389);
  if (!port) exit(0);
}
else port = 389;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);

ldap_init(socket:soc);

bind = ldap_bind_request();
ret = ldap_request_sendrecv(data:bind);

if (!isnull(ret) && ret[0] == LDAP_BIND_RESPONSE)
{
 # Register and report the service.
 register_service(port:port, ipproto:"tcp", proto:"ldap");

 security_note(port);
}
