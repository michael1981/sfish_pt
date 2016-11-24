#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38745);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-3529", "CVE-2009-0162", "CVE-2009-0945", "CVE-2009-2058");
  script_bugtraq_id(31126, 34924, 34925, 35380);
  script_xref(name:"OSVDB", value:"48158");
  script_xref(name:"OSVDB", value:"54454");
  script_xref(name:"OSVDB", value:"55130");
  script_xref(name:"Secunia", value:"35056");

  script_name(english:"Safari < 3.2.3");
  script_summary(english:"Checks Safari's version number");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host contains a web browser that is affected by several\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Safari installed on the remote Windows host is earlier\n",
      "than 3.2.3.  Such versions are potentially affected by several issues :\n",
      "\n",
      "  - A heap buffer overflow issue in the libxml library when\n",
      "    handling long entity names could lead to a crash or\n",
      "    arbitrary code execution. (CVE-2008-3529)\n",
      "\n",
      "  - Multiple input validation issues exist in Safari's\n",
      "    handling of 'feed:' URLs, which could be abused to\n",
      "    execute arbitrary JavaScript code. (CVE-2009-0162)\n",
      "\n",
      "  - A memory corruption issue in WebKit's handling of\n",
      "    SVGList objects could lead to arbitrary code execution.\n",
      "    (CVE-2009-0945)\n",
      "\n",
      "  - The browser uses the HTTP Host header to determine the\n",
      "    context of a 4xx/5xx CONNECT response from a proxy server.\n",
      "    This could allow a man-in-the-middle attacker to execute\n",
      "    arbitrary script code in the context of a legitimate server,\n",
      "    circumventing the browser's same-origin policy. (CVE-2009-2058)"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://research.microsoft.com/apps/pubs/default.aspx?id=79323"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3550"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/may/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Safari 3.2.3 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");

  exit(0);
}


include("global_settings.inc");


ver = get_kb_item("SMB/Safari/FileVersion");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 3 ||
  (
    iver[0] == 3 &&
    (
      iver[1] < 525 ||
      (iver[1] == 525 && iver[2] < 29)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    prod_ver = get_kb_item("SMB/Safari/ProductVersion");
    if (!isnull(prod_ver)) ver = prod_ver;

    report = string(
      "\n",
      "Safari version ", ver, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
