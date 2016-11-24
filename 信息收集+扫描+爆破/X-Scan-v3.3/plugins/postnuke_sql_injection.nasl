#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
 script_id(11744);
 script_version("$Revision: 1.13 $");
 script_bugtraq_id(7697);
 script_xref(name:"OSVDB", value:"5496");

 script_name(english:"PostNuke Glossary Module page Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to an SQL Injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PostNuke which is vulnerable
to a SQL injection attack.

An attacker may use this flaw to gain the control of the database
of this host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of PostNuke." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Determines if PostNuke is vulnerable to SQL injection");
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


if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

r = http_send_recv3(method: "GET", port: port, item:string(dir, "/modules.php?op=modload&name=Glossary&file=index&page='"));
if (isnull(r)) exit(0);
 
if ("hits=hits+1 WHERE" >< r[0]+r[1]+r[2])
{
 security_hole(port);
 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}

