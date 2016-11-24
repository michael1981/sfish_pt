#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15784);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2004-1537", "CVE-2004-1538", "CVE-2005-2683", "CVE-2005-2699", "CVE-2005-3552",
               "CVE-2005-3553", "CVE-2005-3554", "CVE-2005-4424", "CVE-2006-0785", "CVE-2006-0786", 
               "CVE-2006-1507", "CVE-2006-1773");
 script_bugtraq_id(11725, 14629, 15354, 17291, 17467);
 script_xref(name:"OSVDB", value:"12109");
 script_xref(name:"OSVDB", value:"18951");
 script_xref(name:"OSVDB", value:"18952");
 script_xref(name:"OSVDB", value:"19092");
 script_xref(name:"OSVDB", value:"20553");
 script_xref(name:"OSVDB", value:"20554");
 script_xref(name:"OSVDB", value:"20555");
 script_xref(name:"OSVDB", value:"20556");
 script_xref(name:"OSVDB", value:"20557");
 script_xref(name:"OSVDB", value:"20558");
 script_xref(name:"OSVDB", value:"20559");
 script_xref(name:"OSVDB", value:"20560");
 script_xref(name:"OSVDB", value:"20561");
 script_xref(name:"OSVDB", value:"20562");
 script_xref(name:"OSVDB", value:"20563");

 script_name(english:"PHP-Kit <= 1.6.1 RC2 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP-Kit, an open-source content management
system written in PHP. 

The remote version of this software is vulnerable to multiple remote
and local code execution, SQL injection and cross-site scripting
flaws." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110117116115493&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=112474427221031&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_212005.80.html" );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/phpkit_161r2_incl_xpl.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/429249/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Remove the application as it is no longer maintained." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Check for SQL Injection in PHPKIT";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port))exit(0);

loc = make_list();

# 1. Detect phpkit
if (thorough_tests) dirs = list_uniq(make_list("/phpkit", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 r = http_send_recv3(method:"GET", item:dir + "/include.php", port:port);
 if (isnull(r)) exit(0, "the web server did not answer");
 res = r[2];
 line = egrep(pattern:".*PHPKIT.* Version [0-9.]*", string:res);
 if ( line )
 {
  version = ereg_replace(pattern:".*PHPKIT.* Version ([0-9.]*).*", string:line, replace:"\1");
  if ( version == line ) version = "unknown";
  if ( dir == "" ) dir = "/";

  set_kb_item(name:"www/" + port + "/phpkit", value:version + " under " + dir);
  loc = make_list(dir, loc);
 }
}

# Now check the SQL injection

foreach dir (loc)
{
 r = http_send_recv3(method:"GET",item:dir + "/popup.php?img=<script>", port:port);
 if (isnull(r)) exit(0, "the web server did not answer");
 res = r[2];
 if  ( 'ALT="<script>" SRC="<script>"' >< res ) 
	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 r = http_send_recv3(method:"GET",item:loc + "/include.php?path=guestbook/print.php&id='", port:port);
 if (isnull(r)) exit(0, "the web server did not answer");
 res = r[2];
 if  ( "SELECT * FROM phpkit_gbook WHERE gbook_id='''" >< res )
	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
}
