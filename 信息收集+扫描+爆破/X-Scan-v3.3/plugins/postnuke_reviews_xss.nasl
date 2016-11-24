#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
 script_id(14189);
 script_version("$Revision: 1.9 $");
 script_bugtraq_id(10802);
 script_xref(name:"OSVDB", value:"8064");

 script_name(english:"PostNuke Reviews Module title Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PostNuke which contains
the 'Reviews' module which itself is vulnerable to a cross site
scripting issue.

An attacker may use this flaw to steal the cookies of the legitimate 
users of this web site." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this module." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Determines if PostNuke is vulnerable to XSS");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencie("postnuke_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
dir = stuff[2];

test_cgi_xss(port: port, dirs: make_list(dir), cgi: "/modules.php",
 pass_str: "<script>foo</script>",
 qs: "op=modload&name=Reviews&file=index&req=showcontent&id=1&title=<script>foo</script>");
