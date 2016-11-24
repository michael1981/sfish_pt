#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19512);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-2734");
  script_bugtraq_id(14668);
  script_xref(name:"OSVDB", value:"19015");

  script_name(english:"Gallery EXIF Data XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Gallery, a web-based photo album. 

According to its banner, the version of Gallery installed on the
remote host is prone to script insertion attacks because it does not
sanitize malicious EXIF data stored in image files.  Using a
specially-crafted image file, an attacker can exploit this flaw to
cause arbitrary HTML and script code to be executed in a user's
browser within the context of the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://cedri.cc/advisories/EXIF_XSS.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-08/0374.html" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=352576" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gallery 1.5.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for EXIF data script insertion vulnerability in Gallery";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Look for Gallery's main page.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (res == NULL) exit(0);

  # Check the version number.
  if (egrep(string:res, pattern:"Powered by <a href=.+>Gallery.* v(0\.|1\.([0-4]\.|5\.(0|1-RC2)))")) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
