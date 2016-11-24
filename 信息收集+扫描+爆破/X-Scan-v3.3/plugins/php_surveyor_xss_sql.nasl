#
# Josh Zlatin-Amishav GPLv2 


include("compat.inc");

if(description)
{
 script_id(19494);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2005-2380", "CVE-2005-2381", "CVE-2005-2398", "CVE-2005-2399");
 script_bugtraq_id(14329, 14331);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"18086");
   script_xref(name:"OSVDB", value:"18087");
   script_xref(name:"OSVDB", value:"18088");
   script_xref(name:"OSVDB", value:"18089");
   script_xref(name:"OSVDB", value:"18090");
   script_xref(name:"OSVDB", value:"18091");
   script_xref(name:"OSVDB", value:"18092");
   script_xref(name:"OSVDB", value:"18093");
   script_xref(name:"OSVDB", value:"18094");
   script_xref(name:"OSVDB", value:"18095");
   script_xref(name:"OSVDB", value:"18096");
   script_xref(name:"OSVDB", value:"18097");
   script_xref(name:"OSVDB", value:"18098");
   script_xref(name:"OSVDB", value:"18099");
   script_xref(name:"OSVDB", value:"18100");
   script_xref(name:"OSVDB", value:"18101");
   script_xref(name:"OSVDB", value:"18102");
   script_xref(name:"OSVDB", value:"18103");
   script_xref(name:"OSVDB", value:"18104");
   script_xref(name:"OSVDB", value:"18105");
   script_xref(name:"OSVDB", value:"18106");
   script_xref(name:"OSVDB", value:"18107");
   script_xref(name:"OSVDB", value:"18108");
 }

 script_name(english:"PHP Surveyor Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP Surveyor, a set of PHP scripts used to
develop, publish and collect responses from surveys. 

The remote version of this software contains multiple vulnerabilities
that can lead to SQL injection, path disclosure and cross-site
scripting." );
 script_set_attribute(attribute:"see_also", value:"http://securityfocus.com/archive/1/405735" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


 summary["english"] = "Checks for SQL injection in admin.php";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2009 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/admin/admin.php?",
     "sid='"
   ), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ( ("<title>PHP Surveyor</title>" >< res) && ("not a valid MySQL result" >< res))
 {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
 }
}
