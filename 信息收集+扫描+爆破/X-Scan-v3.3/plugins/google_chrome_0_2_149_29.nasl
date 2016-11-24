#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34197);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-6994", "CVE-2008-6995", "CVE-2008-6997", "CVE-2008-6998");
  script_bugtraq_id(30983, 31029, 31038, 31071);
  script_xref(name:"OSVDB", value:"47908");
  script_xref(name:"OSVDB", value:"48259");
  script_xref(name:"OSVDB", value:"48260");
  script_xref(name:"OSVDB", value:"48261");
  script_xref(name:"OSVDB", value:"48264");

  script_name(english:"Google Chrome < 0.2.149.29 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 0.2.149.29.  Such versions are reportedly are affected by several
issues :

  - A buffer overflow involving long filenames that display 
    in the 'Save As...' dialog could lead to arbitrary code 
    execution (Issue #1414).

  - A buffer overflow in handling of link targets displayed 
    in the status area when a user hovers over a link could 
    lead to arbitrary code execution (Fix #1797).

  - An out-of-bounds memory read when parsing URLs ending in 
    ':%' could cause the application itself to crash (Issue 
    #122).

  - The default Downloads directory is set to Desktop, which
    could lead to malicious cluttering of the desktop with 
    unwanted downloads and even execution of arbitrary
    programs (Fix #17933)." );
 script_set_attribute(attribute:"see_also", value:"http://code.google.com/p/chromium/issues/detail?id=122" );
 script_set_attribute(attribute:"see_also", value:"http://code.google.com/p/chromium/issues/detail?id=1414" );
 script_set_attribute(attribute:"see_also", value:"http://googlechromereleases.blogspot.com/2008/09/beta-release-0214929.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 0.2.149.29." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");
  exit(0);
}

#

include("global_settings.inc");


# Check each installation.
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
    ver[0] == 0 &&
    (
      ver[1] < 2 ||
      (
        ver[1] == 2 &&
        (
          ver[2] < 149 ||
          (ver[2] == 149 && ver[3] < 29)
        )
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
      info += '\n';
    }

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
        # nb: report already has an extra blank line at the end.
        "Note that Nessus only looked in the registry for evidence of Google\n",
        "Chrome.  If there are multiple users on this host, you may wish to\n",
        "enable 'Thorough tests' and re-scan.  This will cause Nessus to scan\n",
        "each local user's directory for installs.\n"
      );
    }
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
