#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  based on work from Tenable Network Security
#
#  Ref: Muhammad Faisal Rauf Danka   <mfrd@attitudex.com> - Gem Internet Services (Pvt) Ltd.
#
#  This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, description touch-up (3/31/2009)


include("compat.inc");

if (description)
{
 script_id(14727);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(5809);
 script_xref(name:"OSVDB", value:"5499");

 script_name(english:"PostNuke News Module article.php sid Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PostNuke which contains the 
'News' module which itself is vulnerable to a cross site scripting issue.

An attacker may use these flaws to steal the cookies of the legitimate 
users of this web site." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of postnuke" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determines if PostNuke is vulnerable to XSS");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_dependencie("postnuke_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
dir = stuff[2];


req = http_get(item:string(dir, "/modules.php?op=modload&name=News&file=article&sid=<script>foo</script>"), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if(res == NULL ) exit(0);
 
if("<script>foo</script>" >< res)
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

