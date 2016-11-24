#
# This script was written by H D Moore
# 
# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, CVSS2 score (1/08/2009)

include("compat.inc");

if(description)
{
    script_id(10993);
    script_version ("$Revision: 1.14 $");

    script_xref(name:"OSVDB", value:"815");

    script_name(english:"Microsoft ASP.NET Application Tracing trace.axd Information Disclosure");
    script_summary(english:"Checks for ASP.NET application tracing");

    script_set_attribute(attribute:"synopsis", value:
"The remote host may be prone to an information disclosure issue." );
    script_set_attribute(attribute:"description", value:
"The ASP.NET web application running in the root directory of this web
server has application tracing enabled.  This would allow an attacker
to view the last 50 web requests made to this server, including
sensitive information like Session ID values and the physical path to
the requested file." );
    script_set_attribute(attribute:"solution", value:
"Set <trace enabled=false> in web.config" );
    script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
    script_set_attribute(attribute:"plugin_publication_date", value:
"2002/06/05");
    script_end_attributes();

    script_category(ACT_ATTACK);

    script_copyright( english:"This script is Copyright (C) 2002-2009 Digital Defense Inc.");

    family["english"] = "CGI abuses";

    script_family(english:family["english"]);
    script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
    script_require_ports("Services/www", 80);
    exit(0);
}


#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);


req = http_get(item:"/trace.axd", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ("Application Trace" >< res)
{
    security_warning(port);
}
