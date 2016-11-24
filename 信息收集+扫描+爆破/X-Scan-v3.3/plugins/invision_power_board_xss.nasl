#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(12101);
 script_version ("$Revision: 1.10 $");

 script_cve_id("CVE-2004-2279");
 script_bugtraq_id(9822);
 script_xref(name:"OSVDB", value:"18505");
 
 script_name(english:"Invision Power Board index.php pop Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"There is a bug in the version of Invision Power Board on the remote
host that makes it vulnerable to cross-site scripting attacks.  An
attacker may exploit this issue to steal the credentials of legitimate
users of this site." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/356742" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "Checks for the presence of an XSS bug in Invision PowerBoard";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);

 script_dependencies("cross_site_scripting.nasl", "invision_power_board_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
    dir = matches[2];

    req = http_get(item:string(dir, "/index.php?s=&act=chat&pop=1;<script>foo</script>"),
 		port:port);
    r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
    if( r == NULL )exit(0);

    if("<script>foo</script>" >< r)
    {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    }
}
