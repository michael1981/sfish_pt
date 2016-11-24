#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15443);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2004-1584");
 script_bugtraq_id(11348);
 script_xref(name:"OSVDB", value:"10595");

 script_name(english:"WordPress wp-login.php HTTP Response Splitting");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to HTTP
splitting attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of WordPress is vulnerable
to an HTTP-splitting attack wherein an attacker can insert CR LF
characters and then entice an unsuspecting user into accessing the URL. 
The client will parse and possibly act on the secondary header which was
supplied by the attacker." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/377770" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 1.2.1 or greater." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for HTTP response splitting vulnerability in WordPress < 1.2.1");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("wordpress_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  # The actual attack requires credentials -> do a banner check.
  ver = matches[1];
  if (ver =~ "(0\.|1\.([01]|2[^0-9]))") { 
    security_warning(port); 
    exit(0); 
  }
}
