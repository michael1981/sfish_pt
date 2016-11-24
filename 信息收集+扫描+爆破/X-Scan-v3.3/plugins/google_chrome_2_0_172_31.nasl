#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39356);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1690", "CVE-2009-1718");
  script_bugtraq_id(35271, 35272);
  script_xref(name:"OSVDB", value:"55042");
  script_xref(name:"OSVDB", value:"55043");
  script_xref(name:"Secunia", value:"35411");

  script_name(english:"Google Chrome < 2.0.172.31 WebKit Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 2.0.172.31. Such versions are reportedly affected by multiple
issues :

  - A memory corruption issue exists in the way the WebKit 
    handles recursion in certain DOM event handlers. 
    Successful exploitation of this issue could allow 
    arbitrary code execution within the Google Chrome 
    sandbox. (CVE-2009-1690)

  - WebKit's handling of drag events is affected by an 
    information disclosure issue. (CVE-2009-1718)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e2e95c8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 2.0.172.31 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");

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
    ver[0] < 2 ||
    (
      ver[0] == 2 && ver[1] == 0 &&
      (
        ver[2] < 172 ||
        (ver[2] == 172 && ver[3] < 31)
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
        "enable 'Thorough tests' and re-scan.  This will cause Nessus to scan\n",
        "each local user's directory for installs.\n"
      );
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
