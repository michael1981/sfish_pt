#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40872);
  script_version("$Revision: 1.1 $");

  script_xref(name:"OSVDB", value:"57009");
  script_xref(name:"Secunia", value:"36253");

  script_name(english:"Kayako SupportSuite Ticket Subject XSS");
  script_summary(english:"Checks version in banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application affected by a
persistent cross-site scripting vulnerability." );

  script_set_attribute(attribute:"description", value:
"The remote host is running Kayako SupportSuite, a web-based
electronic support portal written in PHP. 

According to its banner, the version of Kayako installed on the remote
host is earlier than 3.60.04.  Such versions are affected by a
persistent cross-site scripting vulnerability.  Specifically, the
installed version fails to sanitize input passed to the subject field
while creating a new support ticket.  An attacker may be able to
exploit this vulnerability by creating a new support ticket with a
specially crafted subject field, and inject arbitrary HTML or script
code into a user's browser which would get executed every time the
support ticket is viewed.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cd093f2" );
  script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2009-08/0067.html" );
  script_set_attribute(attribute:"see_also", value:"http://forums.kayako.com/f3/3-60-04-stable-available-now-23453/" );

  script_set_attribute(attribute:"solution", value:
"Upgrade to Kayako SupportSuite 3.60.04 or later." );

  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server does not support PHP scripts.");

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/kayako", "/helpdesk", "/esupport", "/support", "/supportsuite", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Grab the initial page.
  url = string(dir, "/index.php");
  res = http_get_cache(item:url, port:port);
  if (isnull(res)) exit(1, "The web server failed to respond.");

  # If so...
  if (
    '- Powered by Kayako SupportSuite Help Desk Software</title>' >< res ||
    '- Powered By Kayako SupportSuite</title>' >< res ||
    '<a href="http://www.kayako.com" target="_blank">Help Desk Software by Kayako SupportSuite' >< res ||
    '<a href="http://www.kayako.com" target="_blank">Help Desk Software By Kayako SupportSuite' >< res ||
    ('>Help Desk Software<' >< res && 'by Kayako SupportSuite' >< res)
  )
  {
    # Get the version.
    version = NULL;
    if ("Kayako SupportSuite v" >< res)
    {
      version = strstr(res, "Kayako SupportSuite v") - "Kayako SupportSuite v";
      version = version - strstr(version, "</a>");
      if (version !~ "^[0-9][0-9.]+[0-9]") version = NULL;
    }

    # Try the admin page if that didn't work.
    if (isnull(version))
    {
      url2 = string(dir, "/admin/index.php");
      res2 = http_send_recv3(method:"GET", item:url2, port:port);
      if (isnull(res2)) exit(1, "The web server failed to respond.");

      if (
        '>Powered by SupportSuite<br/>' >< res2[2] &&
        '<td width="144" align="left"' >< res2[2]
      )
      {
        version = strstr(res2, '<td width="144" align="left"') - '<td width="144" align="left"';
        version = version - strstr(version, "</font>");
        version = strstr(version, "<font");
        version = strstr(version, ">") - ">";
        if (version !~ "^[0-9][0-9.]+[0-9]") version = NULL;
      }
    }

    if (!isnull(version))
    {
      ver = split(version, sep:'.', keep:FALSE);
      for (i=0; i<max_index(ver); i++)
        ver[i] = int(ver[i]);

      # nb: make sure we have at least three components since we're 
      #     testing for 3 (might not be needed).
      while (i < 3)
        ver[i++] = 0;

      if (
        ver[0] < 3 ||
        (
          ver[0] == 3 &&
          (
            ver[1] < 60 ||
            (ver[1] == 60 && ver[2] < 4)
          )
        )
      )
      {
        set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

        if (report_verbosity > 0)
        {
          report = string(
            "\n",
            "Version : ", version, "\n",
            "URL     : ", build_url(port:port, qs:url), "\n"
          );
          security_warning(port:port, extra:report);
        }
        else security_warning(port);
        exit(0);
      }
      else exit(0, "Kayako SupportSuite "+version+" is not affected.");
    }
  }
}
exit(1, "Kayako SupportSuite was not found.");
