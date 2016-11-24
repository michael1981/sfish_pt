#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19513);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2737");
  script_bugtraq_id(14671);
  script_xref(name:"OSVDB", value:"19017");

  script_name(english:"PhotoPost PHP Pro EXIF Data XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PhotoPost PHP Pro installed on
the remote host is prone to script insertion attacks because it does
not sanitize malicious EXIF data stored in image files.  Using a
specially-crafted image file, an attacker can exploit this flaw to
cause arbitrary HTML and script code to be executed in a user's
browser within the context of the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://cedri.cc/advisories/EXIF_XSS.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-08/0374.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for EXIF data script insertion vulnerability in PhotoPost PHP Pro";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("photopost_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/photopost"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([0-4]\.|5\.(0|1($|\.0)))")
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
