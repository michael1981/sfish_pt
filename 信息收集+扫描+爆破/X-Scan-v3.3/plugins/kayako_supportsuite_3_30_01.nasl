#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34029);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-3700", "CVE-2008-3701");
  script_bugtraq_id(30642);
  script_xref(name:"OSVDB", value:"47613");
  script_xref(name:"OSVDB", value:"47614");
  script_xref(name:"OSVDB", value:"47615");
  script_xref(name:"OSVDB", value:"47616");
  script_xref(name:"Secunia", value:"31431");

  script_name(english:"Kayako SupportSuite < 3.30.01 Multiple Vulnerabilities");
  script_summary(english:"Checks version in banner");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application affected by several
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Kayako SupportSuite, a web-based electronic
support portal written in PHP. 

According to its banner, the version of Kayako installed on the remote
host is earlier than 3.30.01 and, as such, affected by several issues:

  - There is a blind SQL injection issue in the staff panel
    that enables a staff user to gain administrative access.

  - A user may be able to inject arbitrary script into a 
    user's browser by opening a ticket or requesting a 
    chat if they include the script in the 'Full Name' 
    field associated with their account.

  - There are numerous cross-site scripting issues." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00123-08092008" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-08/0111.html" );
 script_set_attribute(attribute:"see_also", value:"http://forums.kayako.com/f3/3-30-01-stable-released-18304/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kayako SupportSuite 3.30.01 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
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
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/kayako", "/helpdesk", "/esupport", "/support", "/supportsuite", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Grab the initial page.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If so...
  if (
    '- Powered by Kayako SupportSuite Help Desk Software</title>' >< res ||
    '- Powered By Kayako SupportSuite</title>' >< res ||
    '<a href="http://www.kayako.com" target="_blank">Help Desk Software by Kayako SupportSuite' >< res ||
    '<a href="http://www.kayako.com" target="_blank">Help Desk Software By Kayako SupportSuite' >< res
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
      r = http_send_recv3(method:"GET",item:string(dir, "/admin/index.php"), port:port);
      if (isnull(r)) exit(0);
      res2 = r[2];

      if (
        '>Powered by SupportSuite<br/>' >< res2 &&
        '<td width="144" align="left"' >< res2
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
            ver[1] < 30 ||
            (ver[1] == 30 && ver[2] < 1)
          )
        )
      )
      {
        set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

        if (report_verbosity)
        {
          report = string(
            "\n",
            "Kayako SupportSuite version ", version, " is installed on the remote host.\n"
          );
          security_warning(port:port, extra:report);
        }
        else security_warning(port);

        exit(0);
      }
    }
  }
}
