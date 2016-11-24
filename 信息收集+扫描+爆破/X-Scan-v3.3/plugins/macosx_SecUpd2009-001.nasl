#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);

include("compat.inc");

if (description)
{
  script_id(35684);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-1861", "CVE-2006-3467", "CVE-2007-1351", "CVE-2007-1352", "CVE-2007-1667",
                "CVE-2007-4565", "CVE-2007-4965", "CVE-2008-1377", "CVE-2008-1379", "CVE-2008-1679",
                "CVE-2008-1721", "CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808", "CVE-2008-1887",
                "CVE-2008-1927", "CVE-2008-2315", "CVE-2008-2316", "CVE-2008-2360", "CVE-2008-2361",
                "CVE-2008-2362", "CVE-2008-2379", "CVE-2008-2711", "CVE-2008-3142", "CVE-2008-3144",
                "CVE-2008-3663", "CVE-2008-4864", "CVE-2008-5031", "CVE-2008-5050", "CVE-2008-5183",
                "CVE-2008-5314", "CVE-2009-0009", "CVE-2009-0011", "CVE-2009-0012", "CVE-2009-0013",
                "CVE-2009-0014", "CVE-2009-0015", "CVE-2009-0017", "CVE-2009-0018", "CVE-2009-0019",
                "CVE-2009-0020", "CVE-2009-0137", "CVE-2009-0138", "CVE-2009-0139", "CVE-2009-0140",
                "CVE-2009-0141", "CVE-2009-0142");
  script_bugtraq_id(25495, 25696, 28715, 28749, 28928, 29705, 30491, 31976, 32207, 32555,
                    33187, 33796, 33798, 33800, 33806, 33808, 33809, 33810, 33811, 33812,
                    33813, 33814, 33815, 33816, 33820, 33821);
  script_xref(name:"OSVDB", value:"40142");
  script_xref(name:"OSVDB", value:"44693");
  script_xref(name:"OSVDB", value:"44730");
  script_xref(name:"OSVDB", value:"45833");
  script_xref(name:"OSVDB", value:"47478");
  script_xref(name:"OSVDB", value:"47479");
  script_xref(name:"OSVDB", value:"47480");
  script_xref(name:"OSVDB", value:"47481");
  script_xref(name:"OSVDB", value:"49832");
  script_xref(name:"OSVDB", value:"50097");
  script_xref(name:"OSVDB", value:"51964");
  script_xref(name:"OSVDB", value:"51965");
  script_xref(name:"OSVDB", value:"51966");
  script_xref(name:"OSVDB", value:"51967");
  script_xref(name:"OSVDB", value:"51968");
  script_xref(name:"OSVDB", value:"51969");
  script_xref(name:"OSVDB", value:"51970");
  script_xref(name:"OSVDB", value:"51971");
  script_xref(name:"OSVDB", value:"51972");
  script_xref(name:"OSVDB", value:"51973");
  script_xref(name:"OSVDB", value:"51974");
  script_xref(name:"OSVDB", value:"51975");
  script_xref(name:"OSVDB", value:"51977");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2009-001)");
  script_summary(english:"Check for the presence of Security Update 2009-001");

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
      "The remote host is running a version of Mac OS X 10.5 or 10.4 that\n",
      "does not have Security Update 2009-001 applied.\n",
      "\n",
      "This security update contains fixes for the following products :\n",
      "\n",
      "  - AFP Server\n",
      "  - Apple Pixlet Video\n",
      "  - CarbonCore\n",
      "  - CFNetwork\n",
      "  - Certificate Assistant\n",
      "  - ClamAV\n",
      "  - CoreText\n",
      "  - CUPS\n",
      "  - DS Tools\n",
      "  - fetchmail\n",
      "  - Folder Manager\n",
      "  - FSEvents\n",
      "  - Network Time\n",
      "  - perl\n",
      "  - Printing\n",
      "  - python\n",
      "  - Remote Apple Events\n",
      "  - Safari RSS\n",
      "  - servermgrd\n",
      "  - SMB\n",
      "  - SquirrelMail\n",
      "  - X11\n",
      "  - XTerm\n"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/ht3438"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/feb/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string("Install Security Update 2009-001 or later.")
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
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
if (!uname) exit(0);

if (egrep(pattern:"Darwin.* (8\.[0-9]\.|8\.1[01]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages");
  if (!packages) exit(0);

  if (!egrep(pattern:"^SecUpd(Srvr)?2009-00[1-5]", string:packages))
    security_hole(0);
}
else if (egrep(pattern:"Darwin.* (9\.[0-6]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(0);

  if (!egrep(pattern:"^com\.apple\.pkg\.update\.security\.2009\.001\.bom", string:packages))
    security_hole(0);
}
