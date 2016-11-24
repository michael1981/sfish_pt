#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
   script_id(17304);
   script_bugtraq_id(6671);
   script_version ("$Revision: 1.14 $");
   
   script_cve_id("CVE-2001-1135", "CVE-1999-0571");
   script_xref(name:"OSVDB", value:"592");
   
   script_name(english:"ZyXEL Routers Default Web Account");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is a router with a default web password set." );
 script_set_attribute(attribute:"description", value:
"The remote host is a ZyXEL router with a default password set.
An attacker could connect to the web interface and reconfigure it." );
 script_set_attribute(attribute:"solution", value:
"Change the password immediately." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

   summary["english"] = "Logs into the ZyXEL web administration";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english: "This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
   script_family(english: "Misc.");
   script_dependencie("http_version.nasl");
   script_require_ports(80);
   exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);
# if ( ! port || port != 80 ) exit(0);

banner = get_http_banner(port:port);
if ( "ZyXEL-RomPager" >!< banner ) exit(0);

r = http_send_recv3(port: port, method: "GET", item: "/", username: "", password: "");
if (isnull(r)) exit(0);
if (r[0] !~ "^HTTP/1\.[01] +401 ") exit(0);

r = http_send_recv3(method: "GET", port: port, item: "/", username: "admin", password: "1234");
if (isnull(r)) exit(0);

if (r[0] =~ "^HTTP/1\.[01] +200 ") security_hole(port);

