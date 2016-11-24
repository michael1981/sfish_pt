#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);

include("compat.inc");

if (description)
{
  script_id(38743);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186", "CVE-2006-0747", "CVE-2007-2754",
                "CVE-2008-2939", "CVE-2008-3529", "CVE-2008-3651", "CVE-2008-3652", "CVE-2008-3790",
                "CVE-2008-3863", "CVE-2008-4309", "CVE-2008-5077", "CVE-2009-0010", "CVE-2009-0021",
                "CVE-2009-0025", "CVE-2009-0114", "CVE-2009-0145", "CVE-2009-0146", "CVE-2009-0147",
                "CVE-2009-0148", "CVE-2009-0149", "CVE-2009-0154", "CVE-2009-0156", "CVE-2009-0158",
                "CVE-2009-0159", "CVE-2009-0160", "CVE-2009-0164", "CVE-2009-0165", "CVE-2009-0519",
                "CVE-2009-0520", "CVE-2009-0846", "CVE-2009-0847", "CVE-2009-0942", "CVE-2009-0943",
                "CVE-2009-0944", "CVE-2009-0946");
  script_bugtraq_id(30087, 30657, 33890, 34408, 34409, 34481, 34550, 34568, 34665, 34805,
                    34932, 34937, 34938, 34939, 34941, 34942, 34947, 34948, 34950, 34952, 34962);
  script_xref(name:"OSVDB", value:"13154");
  script_xref(name:"OSVDB", value:"13155");
  script_xref(name:"OSVDB", value:"13156");
  script_xref(name:"OSVDB", value:"26032");
  script_xref(name:"OSVDB", value:"36509");
  script_xref(name:"OSVDB", value:"47374");
  script_xref(name:"OSVDB", value:"47460");
  script_xref(name:"OSVDB", value:"47474");
  script_xref(name:"OSVDB", value:"47753");
  script_xref(name:"OSVDB", value:"48158");
  script_xref(name:"OSVDB", value:"49224");
  script_xref(name:"OSVDB", value:"49524");
  script_xref(name:"OSVDB", value:"51164");
  script_xref(name:"OSVDB", value:"51368");
  script_xref(name:"OSVDB", value:"52747");
  script_xref(name:"OSVDB", value:"52748");
  script_xref(name:"OSVDB", value:"52749");
  script_xref(name:"OSVDB", value:"53383");
  script_xref(name:"OSVDB", value:"53385");
  script_xref(name:"OSVDB", value:"53593");
  script_xref(name:"OSVDB", value:"54068");
  script_xref(name:"OSVDB", value:"54069");
  script_xref(name:"OSVDB", value:"54070");
  script_xref(name:"OSVDB", value:"54438");
  script_xref(name:"OSVDB", value:"54440");
  script_xref(name:"OSVDB", value:"54441");
  script_xref(name:"OSVDB", value:"54443");
  script_xref(name:"OSVDB", value:"54444");
  script_xref(name:"OSVDB", value:"54445");
  script_xref(name:"OSVDB", value:"54446");
  script_xref(name:"OSVDB", value:"54450");
  script_xref(name:"OSVDB", value:"54451");
  script_xref(name:"OSVDB", value:"54452");
  script_xref(name:"OSVDB", value:"54461");
  script_xref(name:"OSVDB", value:"54495");
  script_xref(name:"OSVDB", value:"54496");
  script_xref(name:"OSVDB", value:"54497");
  script_xref(name:"OSVDB", value:"56273");
  script_xref(name:"OSVDB", value:"56274");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2009-002)");
  script_summary(english:"Check for the presence of Security Update 2009-002");

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
      "have Security Update 2009-002 applied.\n",
      "\n",
      "This security update contains fixes for the following products :\n",
      "\n",
      "  - Apache\n",
      "  - ATS\n",
      "  - BIND\n",
      "  - CoreGraphics\n",
      "  - Cscope\n",
      "  - CUPS\n",
      "  - Disk Images\n",
      "  - enscript\n",
      "  - Flash Player plug-in\n",
      "  - Help Viewer\n",
      "  - IPSec\n",
      "  - Kerberos\n",
      "  - Launch Services\n",
      "  - libxml\n",
      "  - Net-SNMP\n",
      "  - Network Time\n",
      "  - OpenSSL\n",
      "  - QuickDraw Manager\n",
      "  - Spotlight\n",
      "  - system_cmds\n",
      "  - telnet\n",
      "  - Terminal\n",
      "  - X11"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3549"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/may/msg00002.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2009-002 or later."
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

  if (!egrep(pattern:"^SecUpd(Srvr)?(2009-00[2-5]|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
