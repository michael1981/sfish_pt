#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(17306);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2005-0697");
 script_bugtraq_id(12740);
 script_xref(name:"OSVDB", value:"14598");

 name["english"] = "CopperExport XP_Publish.PHP SQL Injection Vulnerability";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CopperExport, a plugin for iPhoto that
allows an iPhoto user to export images to a Coppermine gallery. 

The remote version of this software fails to sanitize unspecified
input to the 'xp_publish.php' script before using it in a SQL query. 

Note that successful exploitation requires that an attacker be
authenticated." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/secunia/2005-q1/0814.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CopperExport 0.2.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "SQL Injection in CopperExport";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


function check(dir)
{
  local_var buf, r;
  global_var port;

  r = http_send_recv3(method:"GET", item:dir + "/ChangeLog", port:port);
  if (isnull(r)) exit(0);
  buf = strcat(r[0], r[1], '\r\n', r[2]);

  if("initial release of CopperExport." ><  buf &&
     "Version 0.2.1" >!< buf )
  	{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80, embedded: 0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) check( dir : dir );
