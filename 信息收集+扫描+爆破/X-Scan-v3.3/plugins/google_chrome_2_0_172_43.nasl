#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40778);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-2414", "CVE-2009-2416", "CVE-2009-2935");
  script_bugtraq_id(36010, 36149);
  script_xref(name:"OSVDB", value:"56985");
  script_xref(name:"OSVDB", value:"56990");
  script_xref(name:"OSVDB", value:"57421");
  script_xref(name:"OSVDB", value:"57422");
  script_xref(name:"Secunia", value:"36207");
  script_xref(name:"Secunia", value:"36417");

  script_name(english:"Google Chrome < 2.0.172.43 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 2.0.172.43.  Such versions are reportedly affected by multiple
issues :

  - A flaw in the V8 JavaScript engine might allow a 
    specially crafted JavaScript page to access 
    unauthorized data in memory or to execute arbitrary code 
    within the Google Chrome sandbox. (CVE-2009-2935)

  - The browser can connect to SSL-enabled sites whose
    certificates use weak hash algorithms, such as MD2 and 
    MD4. An attacker may be able exploit this issue to 
    forge certificates and spoof an invalid website as a 
    valid HTTPS site. (#18725)

  - A stack consumption vulnerability in libxml2 library 
    could be exploited to crash the Google Chrome tab process 
    or execute arbitrary code with in Google Chrome sandbox.
    (CVE-2009-2414) 

  - Multiple use-after-free vulnerabilities in libxml2 
    library could be exploited to crash the Google Chrome 
    tab process or execute arbitrary code with in Google 
    Chrome sandbox. (CVE-2009-2416)");

  script_set_attribute(attribute:"see_also", value:"http://code.google.com/p/chromium/issues/detail?id=18639" );
  script_set_attribute(attribute:"see_also", value:"http://code.google.com/p/chromium/issues/detail?id=18725" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3047265" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 2.0.172.43 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/26");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("global_settings.inc");

# Check each installation.
installs = get_kb_list("SMB/Google_Chrome/*");
if (isnull(installs)) exit(1, "The 'SMB/Google_Chrome' KB list is missing.");

info = "";
vulns = make_array();

foreach install(sort(keys(installs)))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Google_Chrome/";
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    ver[0] < 2 ||
    (
      ver[0] == 2 && ver[1] == 0 &&
      (
        ver[2] < 172 ||
        (ver[2] == 172 && ver[3] < 43)
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
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
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
      "the remote host :\n\n",
      info
    );
    if (!thorough_tests)
    {
      report = string(
        report,
        "Note that Nessus only looked in the registry for evidence of Google\n",
        "Chrome. If there are multiple users on this host, you may wish to\n",
        "enable 'Thorough tests' and re-scan. This will cause Nessus to scan\n",
        "each local user's directory for installs.\n"
      );
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else 
{
  if (thorough_tests) exit(0,"No vulnerable versions of Google Chrome were found.");
  else exit(1, "Some installs may have been missed because 'Thorough tests' was not enabled.");
}
