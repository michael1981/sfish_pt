#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(39852);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2009-1692", "CVE-2009-2555", "CVE-2009-2556");
  script_bugtraq_id(35446, 35722, 35723);
  script_xref(name:"OSVDB", value:"55242");
  script_xref(name:"OSVDB", value:"55939");
  script_xref(name:"OSVDB", value:"56245");
  script_xref(name:"Secunia", value:"35844");

  script_name(english:"Google Chrome < 2.0.172.37 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 2.0.172.37.  Such versions are reportedly affected by multiple
issues :

  - A heap overflow exists when evaluating specially crafted
    regular expressions in JavaScript. This could lead to a
    denial of service or the execution of arbitrary code
    within the Google Chrome sandbox.

  - A memory corruption issue exists in the renderer process
    that could cause a denial of service or possibly allow
    arbitrary code execution with the privileges of the
    logged on user.

  - Creating a Select object with a very large length can
    result in memory exhaustion, causing a denial of service." );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/504969/100/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f3cdeb6" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 2.0.172.37 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/17");

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
if (isnull(installs)) exit(0, "Did not detect Google Chrome");

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
        (ver[2] == 172 && ver[3] < 37)
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
