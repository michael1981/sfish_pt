#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPLv2
# Ref: Erik Sjölund
# 

# Changes by Tenable:
# - Revised plugin title (4/7/2009)


include("compat.inc");

if(description)
{
 script_id(16387);
 script_version ("$Revision: 1.12 $"); 

 script_cve_id("CVE-2005-0073");
 script_bugtraq_id(12527);
 script_xref(name:"OSVDB", value:"13707");

 script_name(english:"Sympa src/queue.c queue Utility Local Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by a
local privilege escalation vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Sympa on the
remote host contains a a boundary error in the queue utility when
processing command line arguments, which can result in a stack-based
buffer overflow.  A malicious local user could leverage this issue
with a long listname to gain privileges of the 'sympa' user when the
script is run setuid." );
 script_set_attribute(attribute:"solution", value:
"Update to Sympa version 4.1.3 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


 summary["english"] = "Checks sympa version";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencies("sympa_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# the code
#

include("global_settings.inc");
include("http_func.inc");


# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/sympa"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];
  if (ver =~ "^(2\.|3\.|4\.0|4\.1\.[012]([^0-9]|$))")
  {
    security_warning(port);
    exit(0);
  }
}
