#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(14787);
 script_version("$Revision: 1.5 $");
 script_bugtraq_id(11103);
 script_xref(name:"OSVDB", value:"9527");

 script_name(english:"phpMyBackupPro < 1.0.0 Unspecified Input Validation Issues");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is affected by several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be using phpMyBackupPro. 

It is reported that the remote version of this software is prone to 
multiple security weaknesses regarding user input validation. 

An attacker may use these issues to gain access to the application or to
access the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.0.0 of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Fetches the version of phpMyBackupPro");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  r = http_send_recv3(method: "GET", item:dir + "/index.php", port:port);
  if (isnull(r)) exit(0);
  if ( "phpMyBackupPro" >< r[2] &&    
       egrep(pattern:"<title>phpMyBackupPro 0\.([0-5]\.[0-9]|6\.[0-2])</title>", string:r[2]) )
	{
	 security_hole(port);
	 exit(0);
	}
 }
