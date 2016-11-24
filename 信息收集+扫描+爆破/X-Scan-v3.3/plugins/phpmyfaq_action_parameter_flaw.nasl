#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# Ref: Stefan Esser <s.esser@e-matters.de>
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (4/24/009)


include("compat.inc");

if(description)
{
 script_id(14258);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2004-2255");
 script_bugtraq_id(10374);
 script_xref(name:"OSVDB", value:"6300");

 script_name(english:"phpMyFAQ index.php action Variable Local File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that permits information
disclosure of local files." );
 script_set_attribute(attribute:"description", value:
"The version of phpMyFAQ on the remote host contains a flaw that may lead
to an unauthorized information disclosure.  The problem is that user
input passed to the 'action' parameter is not properly verified before
being used to include files, which could allow an remote attacker to
view any accessible file on the system, resulting in a loss of
confidentiality." );
 script_set_attribute(attribute:"see_also", value:"http://security.e-matters.de/advisories/052004.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyfaq.de/advisory_2004-05-18.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyFAQ 1.3.13 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Check the version of phpMyFAQ");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("phpmyfaq_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))
	exit(0);
if ( ! can_host_php(port:port) ) 
	exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpmyfaq"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "(0\.|1\.([0-2]\.|3\.([0-9]($|[^0-9])|1[0-2])))") security_warning(port);
}
