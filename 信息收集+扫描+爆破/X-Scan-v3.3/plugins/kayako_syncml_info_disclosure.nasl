#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30053);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-0395");
  script_xref(name:"OSVDB", value:"40517");

  script_name(english:"Kayako SupportSuite syncml/index.php Direct Request Remote Information Disclosure");
  script_summary(english:"Requests Kayako's syncml/index.php script");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The version of Kayako installed on the remote host returns PHP's
'$_SERVER' superglobal variable in response to a request for Kayako's
'syncml/index.php' page.  This variable contains information about the
remote web server, some of which might be sensitive." );
 script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-63.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/486762/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
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

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/kayako", "/helpdesk", "/esupport", "/support", "/supportsuite", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  url = string(dir, "/syncml/index.php");

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it's affected.
  if (
    'Array' >< res &&
    egrep(pattern:"\[(DOCUMENT_ROOT|PATH|QUERY_STRING)\] =>", string:res)
  )
  {
    # Make sure it's Kayako unless we're being paranoid.
    vuln = FALSE;
    if (report_paranoia < 2)
    {
      if (strlen(dir) == 0) dir = "/";
      r = http_send_recv3(method:"GET", item:dir, port:port);
      if (isnull(r)) exit(0);
      res2 = r[2];

      if ("Powered by Kayako" >< res2) vuln = TRUE;
    }
    else vuln = TRUE;

    if (vuln)
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to obtain the contents of PHP's '$_SERVER'\n",
          "superglobals array from the remote host using the following URL :\n",
          "\n",
          "  ", build_url(port: port, qs: url), "\n"
        );
        if (report_verbosity > 1)
        {
          report = string(
            report,
            "\n",
            "Here are the contents :\n",
            "\n",
            res
          );
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
