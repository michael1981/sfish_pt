#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(16197);
 script_bugtraq_id(12290);
 script_xref(name:"OSVDB", value:"12967");
 script_xref(name:"OSVDB", value:"12968");
 script_xref(name:"OSVDB", value:"13003");
 script_xref(name:"OSVDB", value:"13004");
 script_xref(name:"OSVDB", value:"13005");
 script_xref(name:"OSVDB", value:"13006");
 script_xref(name:"OSVDB", value:"13007");
 script_version("$Revision: 1.6 $");

 script_name(english:"ITA Forum Multiple Scripts SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
multiple SQL injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ITA Forum, a forum software written in PHP.

There is a SQL injection issue in the remote version of this software 
which may allow an attacker to execute arbitrary SQL statements on the
remote host and to potentially overwrite arbitrary files on the remote 
system, by sending a malformed value to several files on the remote 
host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/exploits/5AP0A1PELU.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "SQL Injection in ITA Forum";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

function check(loc)
{
 local_var res;

 res = http_send_recv3(method:"GET", item:string(loc, "/search.php?Submit=true&search=');"), port:port);
 if (isnull(res)) exit(1, "The remote web server did not respond.");
 
 if ( "mysql_fetch_array()" >< res[2] &&
      "Powered by ITA Forum" >< res[2] ) {
	 security_hole(port);
	 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	 exit(0);
	}
}


foreach dir (cgi_dirs()) 
 {
  check(loc:dir);
 }
