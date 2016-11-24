#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34742);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(32258);
  script_xref(name:"OSVDB", value:"52638");

  script_name(english:"Google Chrome < 0.3.154.9 Address Bar Spoofing");
  script_summary(english:"Checks version number of Google Chrome");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by an address
spoofing vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 0.3.154.9.  Such versions are reportedly are affected by an
address spoofing vulnerability in pop-ups.  An attacker can leverage
this issue to manipulate a window's address bar to show a different
address than the actual origin of the content." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/498232/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://googlechromereleases.blogspot.com/2008/10/beta-release-031549.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 0.3.154.9 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

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
      ver[1] < 3 ||
      (
        ver[1] == 3 &&
        (
          ver[2] < 154 ||
          (ver[2] == 154 && ver[3] < 9)
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
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
