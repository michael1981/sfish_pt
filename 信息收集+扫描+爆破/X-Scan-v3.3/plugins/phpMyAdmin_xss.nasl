#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: Cedric Cochin
#
#  This script is released under the GNU GPL v2

# Changes by Tenable:
# - Revised plugin title (4/24/009)


include("compat.inc");

if(description)
{
 script_id(15770);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2004-1055");
 script_bugtraq_id(11707); 
 script_xref(name:"OSVDB", value:"11930");
 script_xref(name:"OSVDB", value:"11931");
 script_xref(name:"OSVDB", value:"11932");
 script_xref(name:"OSVDB", value:"12238");

 script_name(english:"phpMyAdmin < 2.6.0-pl3 Multiple XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The version of phpMyAdmin installed on the remote host is vulnerable
to cross-site scripting attacks through various parameters and
scripts.  With a specially crafted URL, an attacker can cause
arbitrary code execution resulting in a loss of integrity." );
 script_set_attribute(attribute:"see_also", value:"http://www.netvigilance.com/html/advisory0005.htm" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2004-3" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 2.6.0-pl3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Checks the version of phpMyAdmin");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("phpMyAdmin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (!can_host_php(port:port) ) exit(0);


# Check an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if ( ereg(pattern:"^(2\.[0-5]\..*|2\.6\.0|2\.6\.0-pl[12]([^0-9]|$))", string:ver))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
