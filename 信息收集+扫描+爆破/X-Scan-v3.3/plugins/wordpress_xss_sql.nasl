#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16023);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(12066);
 script_xref(name:"OSVDB", value:"10410");
 script_xref(name:"OSVDB", value:"12617");
 script_xref(name:"OSVDB", value:"12621");
 script_xref(name:"OSVDB", value:"53612");
 script_xref(name:"OSVDB", value:"53613");

 script_name(english:"WordPress < 1.5.1 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains multiple PHP scripts that are prone to
SQL injection and cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of WordPress is vulnerable
to a cross-site scripting attack that may allow an attacker to use the
remote server to steal the cookies of third party users on the remote
site. 

In addition, the remote version of this software is vulnerable to a
SQL injection attack that may allow an attacker to manipulate database
queries." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/385042" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 1.5.1 or greater." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the presence of WordPress");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("wordpress_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  # The actual attack requires credentials -> do a banner check
  ver = matches[1];
  if (ver =~ "(0\\.|1\\.([01]|2[^0-9]|2\\.[0-2][^0-9]))") { 
    security_warning(port); 
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
