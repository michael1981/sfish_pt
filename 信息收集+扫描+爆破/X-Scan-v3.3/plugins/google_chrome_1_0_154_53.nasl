#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39449);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-2060", "CVE-2009-2071");
  script_bugtraq_id(35380, 35411);
  script_xref(name:"OSVDB", value:"55132");
  script_xref(name:"OSVDB", value:"56488");
  
  script_name(english:"Google Chrome < 1.0.154.53 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple 
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 1.0.154.53.  Such versions are reportedly affected by multiple
vulnerabilities :

  - The browser uses the HTTP Host header to determine the
    context of a 4xx/5xx CONNECT response from a proxy 
    server. This could allow a man-in-the-middle attacker 
    to execute arbitrary script code in the context of a 
    legitimate server, circumventing the browser's same-
    origin policy. 

  - The browser displays a cached certificate for 4xx/5xx 
    CONNECT response pages from a proxy server.  A man-in-
    the-middle attacker could exploit this by displaying a 
    spoofed web page with the valid certificate of a 
    legitimate website.");
  script_set_attribute(attribute:"see_also", value:
"http://research.microsoft.com/apps/pubs/default.aspx?id=79323" );
  script_set_attribute(attribute:"see_also", value:
"http://sites.google.com/a/chromium.org/dev/getting-involved/dev-channel/release-notes/releasenotes1015453" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 1.0.154.53 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("global_settings.inc");

# Check each installation
installs = get_kb_list("SMB/Google_Chrome/*");
if (isnull(installs)) exit(0);

info = "";
vulns = make_array();

foreach install (sort(keys(installs)))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Google_Chrome/";
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);
  
  if (
    ver[0] < 1 ||
    (
      ver[0] == 1 && ver[1] == 0 &&
      (
        ver[2] < 154 ||
        (ver[2] == 154 && ver[3] < 53)
      )
    )
  )
  {
    path = installs[install];

    if (vulns[version]) vulns[version] += ";" + path;
    else vulns[version] = path;
  }
}

# Report if vulnerable installs were found.
if (max_index(keys(vulns)))
{
  if (report_verbosity)
  {
    info = "";
    n = 0;
    foreach version (sort(keys(vulns)))
    {
      info += '  ' + version + ', installed under :\n';

      foreach path (sort(split(vulns[version], sep:";", keep:FALSE)))
      {
        n++;
        info += '    - ' + path + '\n';
      }
    }
    info += '\n';

    if (n > 1) s = "s of Google Chrome are";
    else s = " of Google Chrome is";

    report = string(
      "\n",
      "The following vulnerable instance", s, " installed on\n",
      "the remote host :\n",
      "\n",
      info
    );
    if (!thorough_tests)
    {
      report = string(
        report,
        "Note that Nessus only looked in the registry for evidence of Google\n",
        "Chrome. If there are multiple users on this host, you may wish to\n",
        "enable 'Thorough tests' and re-scan.  This will cause Nessus to scan\n",
        "each local user's directory for installs.\n"
      );
    }
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
