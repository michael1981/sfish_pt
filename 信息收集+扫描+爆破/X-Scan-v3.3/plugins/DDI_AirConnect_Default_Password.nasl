#
# This script was written by H D Moore
# Information about the AP provided by Brian Caswell
#
# Chnages by Tenable :
#
# Added CVSS2 score, revised desc, updated severity.
#

include("compat.inc");

if(description)
{
    script_id(10961);
    script_version("$Revision: 1.14 $");

    script_cve_id("CVE-1999-0508");
    script_xref(name:"OSVDB", value:"785");

    script_name(english:"AirConnect Default Password");
    script_summary(english:"3Com AirConnect AP Default Password");

    script_set_attribute(attribute:"synopsis", value:
"It is possible to access the remote wireless access point with default
credentials.");
    script_set_attribute(attribute:"description", value:
"This AirConnect wireless access point still has the default password
set for the web interface.  This could be abused by an attacker to
gain full control over the wireless network settings.");
script_set_attribute(attribute:"solution", value:
"Change the password to something difficult to guess via the web
interface.");
    script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_set_attribute(attribute:"plugin_publication_date", value:
"2002/05/22");
    script_end_attributes();

    script_category(ACT_ATTACK);

    script_copyright(english:"This script is Copyright (C) 2002-2009 Digital Defense Inc.");

    family["english"] = "Misc.";
    script_family(english:family["english"]);
    script_dependencie("http_version.nasl");
    script_require_keys("Services/www");
    
    exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

function sendrequest (request, port)
{
    local_var reply;
    reply = http_keepalive_send_recv(data:request, port:port);
    if( isnull(reply) ) exit(0);
    return(reply);
}

#
# The script code starts here
#

port = get_http_port(default:80);

req = string("GET / HTTP/1.0\r\nAuthorization: Basic Y29tY29tY29tOmNvbWNvbWNvbQ==\r\n\r\n");

reply = sendrequest(request:req, port:port);

if ("SecuritySetup.htm" >< reply)
{
    security_hole(port:port);
}
