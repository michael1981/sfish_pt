#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(40501);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-1372", "CVE-2009-0040", "CVE-2009-1720", "CVE-2009-1721",
                "CVE-2009-1722", "CVE-2009-1726", "CVE-2009-2191");
  script_bugtraq_id(28286, 33827, 35838);
  script_xref(name:"OSVDB", value:"43425");
  script_xref(name:"OSVDB", value:"53315");
  script_xref(name:"OSVDB", value:"53316");
  script_xref(name:"OSVDB", value:"53317");
  script_xref(name:"OSVDB", value:"56707");
  script_xref(name:"OSVDB", value:"56708");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2009-003)");
  script_summary(english:"Check for the presence of Security Update 2009-003");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host is missing a Mac OS X update that fixes various\n",
      "security issues."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running a version of Mac OS X 10.4 that does not\n",
      "have Security Update 2009-003 applied.\n",
      "\n",
      "This security update contains fixes for the following products :\n",
      "\n",
      "  - bzip2\n",
      "  - ColorSync\n",
      "  - ImageIO\n",
      "  - Login Window"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3757"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/aug/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2009-003 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/05"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/05"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/05"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");
  exit(0);
}

#

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

if (egrep(pattern:"Darwin.* (8\.[0-9]\.|8\.1[01]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages");
  if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

  if (!egrep(pattern:"^SecUpd(Srvr)?(2009-00[3-5]|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
else exit(0, "The host is not affected.");
