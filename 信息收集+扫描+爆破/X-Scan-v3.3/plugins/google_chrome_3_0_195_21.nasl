#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41000);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-3263", "CVE-2009-3264");
  script_bugtraq_id(36416);
  script_xref(name:"OSVDB", value:"58192");
  script_xref(name:"OSVDB", value:"58193");
  script_xref(name:"Secunia", value:"36770");

  script_name(english:"Google Chrome < 3.0.195.21 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 3.0.195.21.  Such versions are reportedly affected by multiple
issues :

  - Google Chrome's inbuilt RSS/ATOM reader renders 
    untrusted JavaScript in an RSS/ATOM feed. Provided a 
    victim connects to a RSS/ATOM feed link controlled by
    an attacker or a trusted website allows injecting 
    arbitrary JavaScript content into the site's RSS or 
    ATOM feed, it may  be possible for an attacker to 
    execute arbitrary JavaScript within the victim's browser. 
    (#21238)

  - It may be possible to bypass the same origin policy via the
    getSVGDocument() function. (#21338)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ee26e61" );
  script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-09/0252.html");
  script_set_attribute(attribute:"see_also", value:"http://code.google.com/p/chromium/issues/detail?id=21238" );
  script_set_attribute(attribute:"see_also", value:"http://code.google.com/p/chromium/issues/detail?id=21338" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 3.0.195.21 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/15");

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
    ver[0] < 3 ||
    (
      ver[0] == 3 && ver[1] == 0 &&
      (
        ver[2] < 195 ||
        (ver[2] == 195 && ver[3] < 21)
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
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else 
{
  if (thorough_tests) exit(0,"No vulnerable versions of Google Chrome were found.");
  else exit(1, "Some installs may have been missed because 'Thorough tests' was not enabled.");
}
