#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11394);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2001-1161");
 script_bugtraq_id(2962);
 script_xref(name:"OSVDB", value:"1887");
 
 script_name(english:"IBM Lotus Domino nsf File Argument XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote server is vulnerable to cross-site scripting, when
requesting a .nsf file with html arguments, as in :

  GET /home.nsf/<img%20src=javascript:alert(document.domain)>" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-07/0022.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-07/0042.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Domino 5.0.9 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
 script_end_attributes();

 
 script_summary(english:"Checks for Lotus Domino XSS");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl", "domino_default_db.nasl", "cross_site_scripting.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

banner = get_http_banner (port:port);
if ("Lotus Domino" >!< banner) exit (0);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

list = get_kb_list(string("www/domino/", port, "/db"));
if(!isnull(list))
{
 file = list[0];
}
else {
	list = get_kb_list(string("www/", port, "/content/extensions/nsf"));
	if(!isnull(list))file = list[0];
	else file = "/home.nsf"; # Maybe we'd better exit now.
}
	
	
r = http_send_recv3(method: "GET", item:string(file,"/<img%20src=javascript:alert(document.domain)>"), port:port);

if (isnull(r)) exit (0);

if("<img src=javascript:alert(document.domain)>" >< r[2] )
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
