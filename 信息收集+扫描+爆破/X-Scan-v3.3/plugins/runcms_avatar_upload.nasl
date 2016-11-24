#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(17987);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-1031");
  script_bugtraq_id(13027);
  script_xref(name:"OSVDB", value:"15309");

  name["english"] = "RunCMS Remote Arbitrary File Upload Vulnerability";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows arbitrary
file uploads." );
 script_set_attribute(attribute:"description", value:
"The remote host is running RunCMS / E-Xoops, a content management
system written in PHP. 

According to its banner, the version of this software installed on the
remote host may allow a user to upload arbitrary files and potentially
run them.  This issue arises if avatar uploads are enabled (they are
not by default)." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/395097" );
 script_set_attribute(attribute:"solution", value:
"Set 'Allow custom avatar upload' to 'No' in 'Custom avatar settings'." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for remote arbitrary file upload vulnerability in RunCMS";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
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


# Identify RunCMS / E-Xoops.
foreach dir (cgi_dirs()) {
  # Try to pull up the user login form.
  r = http_send_recv3(method:"GET", item:string(dir, "/user.php"), port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);

  # Check the version number.
  #
  # nb: there does not appear to be a way to check if avatar 
  #     uploads are enabled short of logging in.
  if (
    # in the page itself or...
    egrep(string:res, pattern:"RUNCMS\.? *(0.+|1\.(0.*|1A?)) +&copy; 20") ||
    # in a generator meta tag or...
    (
      egrep(string:res, pattern:"^X-Meta-Generator: *(RUNCMS )?(0.+|1\.(0.*|1A?))") &&
      "function xoops" >< res
    ) ||
    # any version of E-Xoops (older than RunCMS but uses the same code).
    "X-Meta-Generator: E-Xoops" >< res ||
    ">Powered by E-Xoops" >< res
  ) {
    security_warning(port);
    exit(0);
  }
}
