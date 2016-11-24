#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(14324);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2004-1730", "CVE-2004-1731", "CVE-2004-1734");
 script_bugtraq_id(10993, 10994, 10995);
 script_xref(name:"OSVDB", value:"9086");
 script_xref(name:"OSVDB", value:"9087");
 script_xref(name:"OSVDB", value:"9088");
 script_xref(name:"OSVDB", value:"9089");
 script_xref(name:"OSVDB", value:"9090");
 script_xref(name:"OSVDB", value:"9091");
 script_xref(name:"OSVDB", value:"9092");

 script_name(english:"Mantis < 0.18.3 / 0.19.0a2 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilties." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of Mantis contains
multiple flaws that may allow an attacker to use it to perform a mass
emailing, to inject HTML tags in the remote pages, or to execute
arbitrary commands on the remote host if PHP's 'register_globals'
setting is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=109312225727345&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=109313416727851&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mantis 0.18.3 or 0.19.0a2 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for the version of Mantis");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("mantis_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mantis"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if(ereg(pattern:"^0\.([0-9]\.|1[0-7]\.|18\.[0-2][^0-9]|19\.0 *a[01]([^0-9]|$))", string:ver))
	security_warning(port);
}	
