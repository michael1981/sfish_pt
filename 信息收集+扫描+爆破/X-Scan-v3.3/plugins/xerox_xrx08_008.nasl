#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33478);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-3121", "CVE-2008-3122");
  script_bugtraq_id(30151);
  script_xref(name:"OSVDB", value:"46816");
  script_xref(name:"OSVDB", value:"46817");
  script_xref(name:"Secunia", value:"30978");

  script_name(english:"XEROX CentreWare Web < 4.6.46 Multiple Vulnerabilities (XRX08-008)");
  script_summary(english:"Checks version in the footer");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"XEROX CentreWare Web, a web-based tool for IP printer management, is
installed on the remote web server. 

According to its banner, the installed version of XEROX CentreWare Web
reportedly contains three areas that are prone to SQL injection
attacks, provided the attacker has valid credentials, and two that are
prone to cross-site scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX08_008.pdf" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to XEROX CentreWare Web version 4.6.46 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
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

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/XeroxCentreWareWeb", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Grab the initial page.
  url = string(dir, "/");
  res = http_get_cache(item:url, port:port);
  if (isnull(res)) exit(0);

  # If it looks like CentreWare Web...
  if (">Xerox CentreWare Web <" >< res)
  {
    # Extract the version number from the footer.
    version = NULL;

    pat = "GFooter.+>Version: [0-9][0-9.]+ \(Build: ([0-9][0-9.]+)\)";
    matches = egrep(pattern:pat, string:res);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }

    # Check the version number.
    if (!isnull(version))
    {
      ver = split(version, sep:'.', keep:FALSE);
      for (i=0; i<max_index(ver); i++)
        ver[i] = int(ver[i]);

      fix = split("4.6.47", sep:'.', keep:FALSE);
      for (i=0; i<max_index(fix); i++)
        fix[i] = int(fix[i]);

      for (i=0; i<max_index(ver); i++)
        if ((ver[i] < fix[i]))
        {
          if (report_verbosity)
          {
            report = string(
              "\n",
              "XEROX CentreWare Web version ", version, " is installed on the remote\n",
              "web server under the following URL :\n",
              "\n",
              "  ", build_url(port:port, qs:url), "\n"
            );
            security_warning(port:port, extra:report);
          }
          else security_warning(port:port);
	  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
          exit(0);
        }
        else if (ver[i] > fix[i])
          break;
    }
  }
}
