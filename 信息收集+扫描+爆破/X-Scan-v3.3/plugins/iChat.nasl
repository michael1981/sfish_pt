#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10110);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0897");

 script_name(english:"iChat Server Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting an application that is affected by 
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"iChat servers up to versions 3.00 allow any user to read arbitrary
files on the target system using a directory traversal attack." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=90538488231977&w=2" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Determines if iChat is vulnerable to a stupid bug");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_require_ports(4080);
 script_dependencies("http_version.nasl");
 exit(0);
}

#
# The script code starts here
#

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:4080);

res = http_send_recv3(method:"GET",item:"../../../../../../../etc/passwd", port:port);
if (isnull(res)) exit(1, "The remote server did not respond to the GET request");

if (egrep(pattern:".*root:.*:0:[01]:.*", string:res[2])) security_warning(port:port);
