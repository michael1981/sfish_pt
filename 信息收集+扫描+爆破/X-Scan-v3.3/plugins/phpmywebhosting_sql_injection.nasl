#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(16208);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-2218");
 script_bugtraq_id(10942);
 script_xref(name:"OSVDB", value:"8976");

 script_name(english:"phpMyWebHosting Authentication SQL Injection"); 
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary SQL statements may be executed on the remote database." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHPMyWebHosting, a webhosting management 
interface written in PHP.

The remote version of this software does not perform a proper validation
of user-supplied input, and is therefore vulnerable to a SQL injection
attack.

An attacker may execute arbitrary SQL statements against the remote 
database by sending a malformed username contain SQL escape characters when 
logging into the remote interface in 'login.php'." );
 script_set_attribute(attribute:"solution", value:
"None at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );



script_end_attributes();

 script_summary(english: "Checks for the presence of PHPMyWebhosting");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


variables = string("PHP_AUTH_USER='&password=&language=english&submit=login");

port = get_http_port(default:80);


foreach dir ( cgi_dirs() )
{
  r = http_send_recv3(method: "POST", item: strcat(dir, "/index.php"), port: port, add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"), data: variables);
  if (isnull(r)) exit(0);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 if ( "SQL" >< buf &&
      " timestamp > date_add" >< buf  && "INTERVAL " >< buf)
   {
	security_hole ( port );
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   }
 
 return(0);
}
