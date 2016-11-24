#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(22318);
 script_version("$Revision: 1.8 $");

 script_name(english:"HP OpenView BBC Service Detection");

 script_summary(english:"Checks for HP OpenView BBC services");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an OpenView service." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running an HP OpenView product.

This specific service is an HTTP server. By sending special requests
(version, info, status, ping, services, ...), it is possible to
obtain information about the remote host." );
 script_set_attribute(attribute:"risk_factor", value:
"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_dependencies("http_version.nasl");
 script_require_ports(383, 3013, 3565);

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = make_list (383, 3013, 3565);

foreach port (ports)
{
 if (!get_port_state(port))
   continue;

 if ("BBC" >!< get_http_banner (port:port))
   continue;

 # can't use http_get else the response is in HTML format
 req = 'GET /Hewlett-Packard/OpenView/BBC/version HTTP/1.0\r\n\r\n';
 r = http_send_recv_buf(port:port, data:req);
 if (isnull(r) || "HP OpenView HTTP Communication Version Report" >!< r[2])
   continue;

 report = string (
 "The following version information has been extracted from the service :\n\n",
	r[2]);

 security_note (port:port, extra:report);
}
