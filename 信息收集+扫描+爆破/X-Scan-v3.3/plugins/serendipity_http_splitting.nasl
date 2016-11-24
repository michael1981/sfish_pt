#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15543);
 script_version ("$Revision: 1.10 $");

 script_cve_id("CVE-2004-1620");
 script_bugtraq_id(11497);
 script_xref(name:"OSVDB", value:"11013");
 script_xref(name:"OSVDB", value:"11038");
 script_xref(name:"OSVDB", value:"11039");

 script_name(english:"Serendipity Multiple Script HTTP Response Splitting");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
cross-site scripting flaw." );
 script_set_attribute(attribute:"description", value:
"The remote version of Serendipity is affected by an HTTP response-
splitting vulnerability that may allow an attacker to perform a cross-
site scripting attack against the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-10/0219.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.s9y.org/5.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serendipity 0.7rc1 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of Serendipity");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("serendipity_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
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
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "0\.([0-6][^0-9]|7-b)")
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
