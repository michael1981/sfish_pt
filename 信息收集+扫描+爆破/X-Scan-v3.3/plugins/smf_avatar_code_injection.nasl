#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19550);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2817");
  script_bugtraq_id(14706);
  script_xref(name:"OSVDB", value:"19120");

  name["english"] = "Simple Machines Forum Avatar Information Disclosure Vulnerability";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows for the
disclosure of information." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Simple Machines Forum (SMF), an open source
web forum application written in PHP. 

The installed version of SMF on the remote host does not properly
sanitize the URI supplied for the user avatar.  An attacker who is
registered in the affected application can exploit this flaw to run
scripts each time a forum user accesses the malicious avatar, eg
collecting forum usage information, launching attacks against users'
systems, etc." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/smf105.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-08/0440.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for avatar code execution vulnerability in Simple Machines Forum";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like Simple Machines Forum and...
    egrep(string:res, pattern:'&copy; 2001.+, <a href="http://www.lewismedia.com/".*>Lewis Media</a>') &&
    # the version number in the banner is <= 1.0.5.
    egrep(string:res, pattern:'style="display.+Powered by <a href="http://www.simplemachines.org/".*>SMF 1\\.0(<| |\\.[0-5])')
  ) {
    security_note(port);
    exit(0);
  }
}
