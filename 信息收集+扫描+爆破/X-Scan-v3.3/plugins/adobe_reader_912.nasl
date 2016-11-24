#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39355);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0198", "CVE-2009-0509", "CVE-2009-0510", "CVE-2009-0511", "CVE-2009-0512", 
                "CVE-2009-0888", "CVE-2009-0889", "CVE-2009-1855", "CVE-2009-1856", "CVE-2009-1857", 
                "CVE-2009-1858", "CVE-2009-1859", "CVE-2009-1861");
  script_bugtraq_id(35274, 35282, 35289, 35291, 35293, 35294, 35295, 35296, 35298,
                    35299, 35300, 35301, 35302, 35303);
  if (NASL_LEVEL >= 3000)
  {
    script_xref(name:"OSVDB", value:"56106");
    script_xref(name:"OSVDB", value:"56107");
    script_xref(name:"OSVDB", value:"56108");
    script_xref(name:"OSVDB", value:"56109");
    script_xref(name:"OSVDB", value:"56110");
    script_xref(name:"OSVDB", value:"56111");
    script_xref(name:"OSVDB", value:"56112");
    script_xref(name:"OSVDB", value:"56113");
    script_xref(name:"OSVDB", value:"56114");
    script_xref(name:"OSVDB", value:"56115");
    script_xref(name:"OSVDB", value:"56116");
    script_xref(name:"OSVDB", value:"56117");
    script_xref(name:"OSVDB", value:"56118");
  }

  script_name(english:"Adobe Reader < 9.1.2 / 8.1.6 / 7.1.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The PDF file viewer on the remote Windows host is affected by multiple\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Adobe Reader installed on the remote host is earlier\n",
      "than 9.1.2 / 8.1.6 / 7.1.3.  Such versions are reportedly affected by\n",
      "multiple vulnerabilities :\n",
      "\n",
      "  - A stack buffer overflow can lead to code execution. \n",
      "    (CVE-2009-1855)\n",
      "\n",
      "  - An integer buffer overflow can result in an application\n",
      "    crash and possibly code execution, although that has\n",
      "    not been shown yet. (CVE-2009-1856)\n",
      "\n",
      "  - A memory corruption issue can result in an application\n",
      "    crash and possibly code execution, although that has\n",
      "    not been shown yet. (CVE-2009-1857)\n",
      "\n",
      "  - A memory corruption issue in the JBIG2 filter can lead\n",
      "    to code execution. (CVE-2009-1858)\n",
      "\n",
      "  - A memory corruption issue can lead to code execution.\n",
      "    (CVE-2009-1859)\n",
      "\n",
      "  - A memory corruption issue in the JBIG2 filter can \n",
      "    result in an application crash and possibly code \n",
      "    execution, although that has not been shown yet. \n",
      "    (CVE-2009-0198)\n",
      "\n",
      "  - Multiple heap buffer overflow vulnerabilities in the\n",
      "    JBIG2 filter can lead to code execution. \n",
      "    (CVE-2009-0509, CVE-2009-0510, CVE-2009-0511, \n",
      "    CVE-2009-0512, CVE-2009-0888, CVE-2009-0889)\n",
      "\n",
      "  - Multiple heap buffer overflow vulnerabilities can lead\n",
      "    to code execution. (CVE-2009-1861)"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.adobe.com/support/security/bulletins/apsb09-07.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Adobe Reader 9.1.2 / 8.1.6 / 7.1.3 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");

  exit(0);
}


include("global_settings.inc");


version = get_kb_item("SMB/Acroread/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 ||
  (
    ver[0] == 7 && 
    (
      ver[1] < 1 ||
      (ver[1] == 1 && ver[2] < 3)
    )
  ) ||
  (
    ver[0] == 8 && 
    (
      ver[1] < 1 ||
      (ver[1] == 1 && ver[2] < 6)
    )
  ) ||
  (
    ver[0] == 9 && 
    (
      ver[1] < 1 ||
      (ver[1] == 1 && ver[2] < 2)
    )
  )
)
{
  version_ui = get_kb_item("SMB/Acroread/Version_UI");
  if (report_verbosity > 0 && version_ui)
  {
    path = get_kb_item("SMB/Acroread/Path");
    if (isnull(path)) path = "n/a";

    report = string(
      "\n",
      "  Product           : Adobe Reader\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version_ui, "\n",
      "  Fix               : 9.1.2 / 8.1.6 / 7.1.3\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
