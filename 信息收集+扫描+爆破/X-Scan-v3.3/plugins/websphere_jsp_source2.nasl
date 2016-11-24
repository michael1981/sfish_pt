#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(23638);
 script_bugtraq_id(20455);
 script_cve_id("CVE-2005-0425");
 script_xref(name:"OSVDB", value:"13770");
 script_version("$Revision: 1.5 $");
 
 script_name(english:"IBM WebSphere Application Server '%20' Request Source Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote web server disclose the source code
of its JSP pages by requesting the .jsp file with a '%20' appended to
the request. 

An attacker may use this flaw to get the source code of your CGIs and
possibly to obtain passwords and other relevant information about this
host." );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?rs=180&uid=swg24013142" );
 script_set_attribute(attribute:"solution", value:
"Apply version 6.1.0 Fix Pack 2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "Attempts to read the source of a jsp page";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(file)
{
    local_var f, pos, w, res;
    global_var port;

    pos[0] = "<%@ page language";
    pos[1] = "<jsp:useBean";
    pos[2] = "<%@ page import";
    w = http_send_recv3(method:"GET ", item: file + "%20", port: port);
    if (isnull(w))
    {
	return 0; 
    }
    else
    {
	res = strcat(w[0], w[1], '\r\n', w[2]);
	foreach f (pos)
	{
	    if (f >< res)
		return 1;
	}
    }
    return 0;

}

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (!banner || "Server: WebSphere Application Server" >!< banner) exit(0);

    files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
    if(isnull(files))
	files = make_list("/index.jsp");
    n = 0;
    foreach file (files)
    {
  	if(check(file:file) == 1)
   	{
	    security_warning(port);
	    exit(0);
  	}
  	n++;
  	if(n > 20)
	    exit(0);
    }
