#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40552);
  script_version("$Revision: 1.2 $");

  script_xref(name:"milw0rm", value:"9401");

  script_name(english:"Spiceworks Accept Request Header Overflow");
  script_summary(english:"Grabs version from login page");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host has an application that is affected by a buffer\n",
      "overflow vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running Spiceworks IT Desktop, an application used\n",
      "to inventory, monitor, manage and report on software and hardware\n",
      "assets in small and medium-sized businesses. \n",
      "\n",
      "The installed version of Spiceworks is earlier than 4.0.  Such\n",
      "versions are reportedly affected by a buffer overflow that can be\n",
      "triggered by sending an overly long 'Accept' request header.  An\n",
      "anonymous remote attacker may be able to leverage this issue to\n",
      "execute arbitrary code on the remote host, subject to the privileges\n",
      "under which the application runs."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://twitter.com/Spiceworks/status/3183604568"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Spiceworks 4.0 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/07"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/06/16"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/11"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9675);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:9675, embedded: 0);

# Grab the login page.
url = "/login";

res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server failed to respond.");

if ('<title>Spiceworks - Login' >< res[2])
{
  # Version info is included in links to .js and .css files.
  pat = '"/(javascripts/[^.]+\\.js|stylesheets/[^.]+\\.css)\\?([0-9]+)"';
  version = NULL;

  matches = egrep(pattern:pat, string:res[2]);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        version = item[2];
        break;
      }
    }
  }

  if (!isnull(version))
  {
    if (
      (strlen(version) == 7 && int(version[0]) < 4) ||
      egrep(pattern:'Copyright &copy; 2006(-0[78])? <', string:res[2])
    )
    {
      if (report_verbosity > 0)
      {
        report = '\n';
        if (strlen(version) == 7)
        {
          report += '  Version : ' + version[0] + "." + version[1] + "." + substr(version, 2) + '\n';
        }
        report += '  URL     : ' + build_url(port:port, qs:url) + '\n';

        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }
    else exit(0, "The remote Spiceworks install is not affected.");
  }
}
