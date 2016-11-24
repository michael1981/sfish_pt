#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40554);
  script_version("$Revision: 1.2 $");

  script_cve_id(
    "CVE-2009-2188",
    "CVE-2009-2195", 
    "CVE-2009-2196",
    "CVE-2009-2199",
    "CVE-2009-2200",
    "CVE-2009-2468"
  );
  script_bugtraq_id(36022, 36023, 36024, 36025, 36026);
  script_xref(name:"OSVDB", value:"56986");
  script_xref(name:"OSVDB", value:"56987");
  script_xref(name:"OSVDB", value:"56988");
  script_xref(name:"OSVDB", value:"56989");

  script_name(english:"Safari < 4.0.3");
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
      "than 4.0.3.  Such versions are potentially affected by several\n",
      "issues :\n",
      "\n",
      "  - A buffer overflow exists in the handling of EXIF \n",
      "    metadata could lead to a crash or arbitrary code \n",
      "    execution. (CVE-2009-2188)\n",
      "\n",
      "  - A vulnerability in WebKit's parsing of floating point\n",
      "    numbers may allow for remote code execution.\n",
      "    (CVE-2009-2195)\n",
      "\n",
      "  - A vulnerability in Safari may let a malicious website to\n",
      "    be promoted in Safari's Top Sites. (CVE-2009-2196)\n",
      "\n",
      "  - A vulnerability in how WebKit renders an URL with look-\n",
      "    alike characters could be used to masquerade a website.\n",
      "    (CVE-2009-2199)\n",
      "\n",
      "  - A vulnerability in WebKit may lead to the disclosure of\n",
      "    sensitive information. (CVE-2009-2200)\n",
      "\n",
      "  - A heap buffer overflow in CoreGraphics involving the drawing of\n",
      "    long text strings could lead to a crash or arbitrary code\n",
      "    execution. (CVE-2009-2468)\n"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3733"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/aug/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17616"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Safari 4.0.3 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/11"
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


path = get_kb_item("SMB/Safari/Path");
version = get_kb_item("SMB/Safari/FileVersion");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 4 ||
  (
    ver[0] == 4 &&
    (
      ver[1] < 531 ||
      (
        ver[1] == 531 && 
        (
          ver[2] < 9 ||
          (ver[2] == 9 && ver[3] < 1)
        )
      )
    )
  )
)
{
  if (report_verbosity > 0)
  {
    if (isnull(path)) path = "n/a";

    prod_version = get_kb_item("SMB/Safari/ProductVersion");
    if (!isnull(prod_version)) version = prod_version;

    report = string(
      "\n",
      "Nessus collected the following information about the current install\n",
      "of Safari on the remote host :\n",
      "\n",
      "  Version : ", version, "\n",
      "  Path    : ", path, "\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
