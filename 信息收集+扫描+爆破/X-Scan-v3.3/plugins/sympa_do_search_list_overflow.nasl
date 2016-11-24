#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# Ref: Paul Johnson <baloo at ursine dot dyndns dot org>
# This script is released under the GNU GPLv2


include("compat.inc");

if(description)
{
 script_id(14298);
 script_version ("$Revision: 1.13 $");

 script_xref(name:"OSVDB", value:"8690");

 name["english"] = "Sympa wwsympa do_search_list Overflow DoS";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is susceptible to a
denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Sympa on the
remote host has a flaw in one of it's scripts (wwsympa.pl) that would
allow a remote attacker to overflow the SYMPA server.  Specifically,
within the cgi script wwsympa.pl is a 'do_search_list' function that
fails to perform bounds checking.  An attacker, passing a specially-
formatted long string to this function, would be able to crash the
remote SYMPA server.  At the time of this writing, the attack is only
known to cause a denial of service." );
 script_set_attribute(attribute:"solution", value:
"Update to version 4.1.2 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks sympa version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencies("sympa_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
if(!get_port_state(port))
	exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/sympa"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];
  # jwl : thru 3.3.5.1 vuln
  if (ver =~ "^([0-2]\.|3\.[0-2]\.|3\.3\.[0-4]|3\.3\.5\.[01]([^0-9]|$))")
  {
    security_warning(port);
    exit(0);
  }
}
