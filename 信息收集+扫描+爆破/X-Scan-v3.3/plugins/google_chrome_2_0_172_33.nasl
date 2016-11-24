#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39492);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-2121");
  script_bugtraq_id(35462, 35463);
  script_xref(name:"OSVDB", value:"55278");
  script_xref(name:"OSVDB", value:"59044");
  script_xref(name:"Secunia", value:"35548");

  script_name(english:"Google Chrome < 2.0.172.33 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host contains a web browser that is affected by multiple\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Google Chrome installed on the remote host is earlier\n",
      "than 2.0.172.33.  Such versions are reportedly affected by multiple\n",
      "issues :\n",
      "\n",
      "  - A buffer overflow caused by handling unspecified HTTP\n",
      "    responses.  This could lead to a denial of service or\n",
      "    execution of arbitrary code. (CVE-2009-2121)\n",
      "\n",
      "  - A denial of service caused by SSL renegotiation.  This could\n",
      "    cause the browser to crash."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://code.google.com/p/chromium/issues/detail?id=13226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0bfaa8f"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Google Chrome 2.0.172.33 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
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
        (ver[2] == 172 && ver[3] < 33)
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
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
