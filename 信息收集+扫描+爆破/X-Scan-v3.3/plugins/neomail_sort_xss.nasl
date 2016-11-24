#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20931);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-0536");
  script_bugtraq_id(16480);
  script_xref(name:"OSVDB", value:"22978");

  script_name(english:"NeoMail neomail.pl sort Parameter XSS");
  script_summary(english:"Checks for sort parameter cross-site scripting vulnerability in NeoMail");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Perl application that is affected by
a cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running NeoMail, an open-source webmail application
written in Perl. 

The installed version of this software fails to validate the 'sort'
parameter in the 'neomail.pl' script before using it to generate
dynamic content.  An attacker may be able to exploit this issue to
inject arbitrary HTML and script code into a user's browser, to be
executed within the security context of the affected application,
resulting in the theft of session cookies and a compromise of a user's
account." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/423901/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to NeoMail version 1.28 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Loop through directories.
foreach dir (cgi_dirs()) {
  # Look for the version number in the banner.
  r = http_send_recv3(method: "GET", item:string(dir, "/neomail.pl"), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if the version's < 1.28.
  if (egrep(pattern:">NeoMail</a> version (0\..+|1\.([01][0-9]|2[0-7])([^0-9].*)?)<BR>", string: r[2])) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
