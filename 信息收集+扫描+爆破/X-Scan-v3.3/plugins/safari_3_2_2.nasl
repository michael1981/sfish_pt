#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35687);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0137", "CVE-2009-2062", "CVE-2009-2072");
  script_bugtraq_id(33234, 35411, 35412);
  script_xref(name:"OSVDB", value:"53991");
  script_xref(name:"OSVDB", value:"56486");
  script_xref(name:"OSVDB", value:"56491");

  script_name(english:"Safari < 3.2.2");
  script_summary(english:"Checks Safari's version number");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host contains a web browser with multiple vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Safari installed on the remote Windows host is earlier\n",
      "than 3.2.2.  Such versions reportedly have multiple security\n",
      "vulnerabilities :\n\n",
      "  - Input validation issues in their handling of 'feed:' URLs, which\n",
      "    could be abused to execute arbitrary JavaScript code in the local\n",
      "    security zone.\n\n",
      "  - A cached certificate is not required before displaying a lock\n",
      "    icon for a HTTPS web site.  This allows a man-in-the-middle\n",
      "    attacker to present the user with spoofed web pages over HTTPS\n",
      "    that appear to be from a legitimate source.\n\n",
      "  - The browser processes a 3xx HTTP CONNECT before a successful\n",
      "    SSL handshake, which could allow a man-in-the-middle attacker\n",
      "    to execute arbitrary script code in the context of a HTTPS site."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://research.microsoft.com/apps/pubs/default.aspx?id=79323"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/ht3439"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/feb/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Safari 3.2.2 or later."
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
      (
        iver[1] == 525 && 
        (
          iver[2] < 28 ||
          (iver[2] == 28 && iver[3] < 1)
        )
      )
    )
  )
)
{
  if (report_verbosity)
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
