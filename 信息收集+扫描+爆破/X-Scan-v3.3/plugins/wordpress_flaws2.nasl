#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15988);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(11984);
 script_xref(name:"OSVDB", value:"12617");
 script_xref(name:"OSVDB", value:"12618");
 script_xref(name:"OSVDB", value:"12619");
 script_xref(name:"OSVDB", value:"12620");
 script_xref(name:"OSVDB", value:"12621");
 script_xref(name:"OSVDB", value:"12622");

 script_name(english:"WordPress < 1.2.2 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to SQL
injection and cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of WordPress is vulnerable
to various flaws which may allow an attacker to perform an HTML
injection attack against the remote host or allow an attacker to execute
arbitrary SQL statements against the remote database." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/384659" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress 1.2.2 or greater." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for multiple flaws in WordPress < 1.2.2");
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
  ver = matches[1];

  if (ver =~ "(0\.|1\.([01]|2[^0-9]|2\.[01][^0-9]))") {
    security_hole(port); 
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
