#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38699);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2009-1441", "CVE-2009-1442");
  script_bugtraq_id(34859);
  script_xref(name:"OSVDB", value:"54248");
  script_xref(name:"OSVDB", value:"54288");
  script_xref(name:"Secunia", value:"35014");

  script_name(english:"Google Chrome < 1.0.154.64 Multiple Overflows");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 1.0.154.64. Such versions are reportedly affected by multiple
vulnerabilities :

  - A failure to properly validate input from a renderer
    (tab) process could allow an attacker to crash the
    browser and possibly run arbitrary code with the
    privileges of the logged on user. (CVE-2009-1441)

  - A failure to check the result of integer multiplication
    when computing image sizes could allow a specially 
    crafted image or canvas to cause a tab to crash and 
    possibly allow an attacker to execute arbitrary code 
    inside the (sandboxed) renderer process. (CVE-2009-1442)" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35c782d6" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 1.0.154.64 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("global_settings.inc");

port = get_kb_item("SMB/transport");
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
        (ver[2] == 154 && ver[3] < 64)
      )
    )
  )
  {
    path = installs[install];

    if (vulns[version]) vulns[version] += ";" + path;
    else vulns[version] = path;
  }
}

# Report if vulnerable installs were found
if (max_index(keys(vulns)))
{
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
      "the remote host :\n",
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
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
}
