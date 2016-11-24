#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
 script_id(11666);
 script_version("$Revision: 1.9 $");

 script_name(english:"PostNuke Sections Module Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PostNuke. It is possible to use the CMS to 
determine the full path to its installation on the server or the name of
the database used, by doing a request like :

/modules.php?op=modload&name=Sections&file=index&req=viewarticle&artid=

An attacker may use these flaws to gain a more intimate knowledge of the
remote host." );
 script_set_attribute(attribute:"solution", value:
"Change the members list privileges to admins only, or disable the 
members list module completely." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Determine if a remote host is vulnerable to the opendir.php vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("postnuke_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
dir = stuff[2];


if(!can_host_php(port:port))exit(0);

u = string(dir, "/modules.php?op=modload&name=Sections&file=index&req=viewarticle&artid=");
r = http_send_recv3(method: "GET", item: u, port:port);
if (isnull(r)) exit(0);
 
if(egrep(pattern:".*/.*/index\.php.*236", string: r[0]+r[1]+r[2]))
 security_warning(port, extra: 
strcat('\nThe following URL exhibits the flaw :\n\n', build_url(port: port, qs: u), '\n'));

