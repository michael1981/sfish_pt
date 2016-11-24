#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(15651);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(11622);

 script_name(english:"Mantis < 0.19.1 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of Mantis suffers from
several information disclosure vulnerabilities that may allow an
attacker to view stats of all projects or to receive information for a
project after he was removed from it." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mantisbt.org/view.php?id=3117" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mantisbt.org/view.php?id=4341" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mantis 0.19.1 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english: "Checks for the version of Mantis");
 
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

  if(ereg(pattern:"^0\.(0?[0-9]\.|1([0-8]\.|9\.0))", string:ver))
	security_warning(port);
	
}
