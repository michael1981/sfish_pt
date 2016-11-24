#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10358);
 script_bugtraq_id(189);
 script_cve_id("CVE-1999-1538");
 script_xref(name:"OSVDB", value:"273");
 script_version ("$Revision: 1.22 $");

 script_name(english:"Microsoft IIS /iisadmin Unrestricted Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a privilege escalation
vulnerability." );
 script_set_attribute(attribute:"description", value:
"When Microsoft Internet Information Server (IIS) 4.0 is upgraded from
version 2.0 or 3.0 the ism.dll file is left in the /scripts/iisadmin
directory. This script discloses sensitive information via a specially
crafted URL which could lead to elevated privileges. An attacker could
use this to gain access to the administrator's password." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=91638375309890&w=2" );
 script_set_attribute(attribute:"solution", value:
"Restrict access to /iisadmin through the IIS ISM." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "Checks for the presence of /iisadmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");
port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( ! banner || "Microsoft-IIS/" >!< banner ) exit(0);
if ( ! get_port_state(port) ) exit(0);

res = http_send_recv3(method:"GET", item:"/iisadmin/", port:port);
if ( ereg(pattern:"HTTP/[01]\.[01] 200 ", string:res[2]) &&
     "<TITLE>IIS Internet Services Manager (HTMLA)</TITLE>" >< res[2] ) security_note(port);
