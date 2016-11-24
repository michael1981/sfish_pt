#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35558);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-0045", "CVE-2007-0048", "CVE-2009-0276", "CVE-2009-0411");
  script_bugtraq_id(21858, 33529, 33773);
  script_xref(name:"OSVDB", value:"31046");
  script_xref(name:"OSVDB", value:"31596");
  script_xref(name:"OSVDB", value:"52641");
  script_xref(name:"OSVDB", value:"54156");

  script_name(english:"Google Chrome < 1.0.154.46 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 1.0.154.46.  Such versions are reportedly affected by several
issues :

  - Cross-site scripting vulnerabilities in the Adobe Reader
    Plugin itself could be leveraged using a PDF document to
    run scripts on arbitrary sites via Google Chrome. 
    (CVE-2007-0048 and CVE-2007-0045)

  - A cross-domain security-bypass vulnerability that could
    allow an attacker to bypass the same-origin policy and
    gain access to potentially sensitive information.
    (CVE-2009-0276)

  - A remote attacker may be able to gain access to the
    'Set-Cookie' and 'Set-Cookie2' response headers via
    XMLHttpRequest calls. (CVE-2009-0411)" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e94a6f2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 1.0.154.46 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
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
    ver[0] < 1 ||
    (
      ver[0] == 1  &&
      (
        ver[1] == 0 &&
        (
          ver[2] < 154 ||
          (ver[2] == 154 && ver[3] < 46)
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
        # nb: report already has an extra blank line at the end.
        "Note that Nessus only looked in the registry for evidence of Google\n",
        "Chrome.  If there are multiple users on this host, you may wish to\n",
        "enable 'Thorough tests' and re-scan.  This will cause Nessus to scan\n",
        "each local user's directory for installs.\n"
      );
    }
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
