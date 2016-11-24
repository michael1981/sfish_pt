#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(16320);
 script_cve_id("CVE-2005-0368");
 script_bugtraq_id(12457);
 script_xref(name:"OSVDB", value:"13573");
 script_xref(name:"OSVDB", value:"13574");
 
 script_version ("$Revision: 1.13 $");
 script_name(english:"Chipmunk CMScore Multiple Script SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple SQL injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Chipmunk CMScore, a web-based software
written in PHP. 

The remote version of this software is affected by several SQL
injection vulnerabilities that may allow an attacker to execute
arbitrary SQL statements using the remote SQL database." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-01/1017.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks if Chipmunk CMScore is vulnerable to a SQL injection attack";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
 if ( is_cgi_installed3(item:dir + "/index.php", port:port) )
 {
   r = http_send_recv3( port: port, method: 'POST', item: dir + "/index.php", 
 data: "searchterm='&submit=submit",
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );

   if (isnull(r)) exit(0);
   if ("<table border='0' width='90%'><tr><td valign='top' width='75%' align='center'><br><br>dies" >< r[2] )
   {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
     exit(0);
   }
  }
}
