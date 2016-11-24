#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42413);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-3931", "CVE-2009-3932");
  script_bugtraq_id(36947);
  script_xref(name:"OSVDB", value:"59742");
  script_xref(name:"OSVDB", value:"59743");
  script_xref(name:"OSVDB", value:"59744");
  script_xref(name:"OSVDB", value:"59745");
  script_xref(name:"Secunia", value:"37273");

  script_name(english:"Google Chrome < 3.0.195.32 Multiple Vulnerabilities");
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
      "than 3.0.195.32.  Such versions are reportedly affected by multiple\n",
      "issues :\n",
      "\n",
      "  - The user is not warned about certain dangerous file\n",
      "    types such as 'SVG', 'MHT', and 'XML'. In some browsers,\n",
      "    JavaScript can execute within these types of files.\n",
      "    (23979)\n",
      "\n",
      "  - A malicious site could use the Gears SQL API to put SQL\n",
      "    metadata into a bad state, which could cause a\n",
      "    subsequent memory corruption which could lead the Gears\n",
      "    plugin to crash, or possibly allow arbitrary code\n",
      "    execution. (26179)\n"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1adc32dc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5c8ae4f"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Google Chrome 3.0.195.32 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/11/05"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/05"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/06"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

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
        (ver[2] == 195 && ver[3] < 32)
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
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else 
{
  if (thorough_tests) exit(0,"No vulnerable versions of Google Chrome were found.");
  else exit(1, "Some installs may have been missed because 'Thorough tests' was not enabled.");
}
