#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12251);
 script_version ("$Revision: 1.4 $");

 script_name(english:"RealServer /admin/Docs/default.cfg Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by an information disclosure." );
 script_set_attribute(attribute:"description", value:
"The remote RealServer seems to allow any anonymous user to download the
default.cfg file.  This file is used to store confidential data and 
should not be accessible via the web frontend." );
 script_set_attribute(attribute:"solution", value:
"Remove or protect this resource." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english: "RealServer default.cfg file search");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/realserver", 7070);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item("Services/realserver");
if (!port) 
	port = 7070;

if (! get_tcp_port_state(port) )
	exit(0);

r = http_send_recv3(method: "GET", item: "/admin/Docs/default.cfg", port:port);
if (isnull(r)) exit(0);

if (egrep(pattern:".*Please read the configuration section of the manual.*", string:r[0]+r[1]+r[2]))
    security_warning(port);
