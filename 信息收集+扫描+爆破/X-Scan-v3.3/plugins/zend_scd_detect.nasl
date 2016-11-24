#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(22270);
  script_version("$Revision: 1.5 $");

  script_name(english:"Zend Session Clustering Daemon Detection");
  script_summary(english:"Detects a Zend Session Clustering daemon");

 script_set_attribute(attribute:"synopsis", value:
"A Zend Session Clustering daemon is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Zend Session Clustering daemon, a
component of the Zend Platform used to synchronize session data across
a cluster of PHP servers." );
 script_set_attribute(attribute:"see_also", value:"http://www.zend.com/products/zend_platform/in_depth#Clustering" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );


script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 34567);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) {
  port = get_unknown_svc(34567);
  if (!port) exit(0);
}
else port = 34567;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a request.
req = "TEN@ABLEBLE";
send(socket:soc, data:req);
res = recv(socket:soc, length:128);
close(soc);


# If ...
if (
  # response is 20 chars long and...
  strlen(res) == 20 &&
  # it looks right.
  substr(res, 0, 6) == "TENABLE"
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"zend_scd");
  security_note(port);
}
