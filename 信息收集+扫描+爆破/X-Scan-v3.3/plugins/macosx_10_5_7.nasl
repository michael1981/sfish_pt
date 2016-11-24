#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);

include("compat.inc");

if (description)
{
  script_id(38744);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186", "CVE-2008-0456", "CVE-2008-1382",
                "CVE-2008-1517", "CVE-2008-2371", "CVE-2008-2383", "CVE-2008-2665", "CVE-2008-2666",
                "CVE-2008-2829", "CVE-2008-2939", "CVE-2008-3443", "CVE-2008-3529", "CVE-2008-3530",
                "CVE-2008-3651", "CVE-2008-3652", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657",
                "CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660", "CVE-2008-3790", "CVE-2008-3863",
                "CVE-2008-4309", "CVE-2008-5077", "CVE-2008-5557", "CVE-2009-0010", "CVE-2009-0021",
                "CVE-2009-0025", "CVE-2009-0040", "CVE-2009-0114", "CVE-2009-0144", "CVE-2009-0145",
                "CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0148", "CVE-2009-0149", "CVE-2009-0150",
                "CVE-2009-0152", "CVE-2009-0153", "CVE-2009-0154", "CVE-2009-0155", "CVE-2009-0156",
                "CVE-2009-0157", "CVE-2009-0158", "CVE-2009-0159", "CVE-2009-0160", "CVE-2009-0161",
                "CVE-2009-0162", "CVE-2009-0164", "CVE-2009-0165", "CVE-2009-0519", "CVE-2009-0520",
                "CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847", "CVE-2009-0942",
                "CVE-2009-0943", "CVE-2009-0944", "CVE-2009-0945", "CVE-2009-0946", "CVE-2009-1717");
  script_bugtraq_id(27409, 29796, 30087, 30649, 30657, 31612, 32948, 33769, 33890, 34257, 34408,
                    34409, 34481, 34550, 34568, 34665, 34805, 34924, 34932, 34937, 34938, 34939,
                    34941, 34942, 34947, 34948, 34950, 34951, 34952, 34958, 34959, 34962, 34965,
                    34972, 34973, 34974, 35182);
  script_xref(name:"OSVDB", value:"13154");
  script_xref(name:"OSVDB", value:"13155");
  script_xref(name:"OSVDB", value:"13156");
  script_xref(name:"OSVDB", value:"41018");
  script_xref(name:"OSVDB", value:"44364");
  script_xref(name:"OSVDB", value:"46584");
  script_xref(name:"OSVDB", value:"46638");
  script_xref(name:"OSVDB", value:"46639");
  script_xref(name:"OSVDB", value:"46641");
  script_xref(name:"OSVDB", value:"46690");
  script_xref(name:"OSVDB", value:"47374");
  script_xref(name:"OSVDB", value:"47460");
  script_xref(name:"OSVDB", value:"47470");
  script_xref(name:"OSVDB", value:"47471");
  script_xref(name:"OSVDB", value:"47472");
  script_xref(name:"OSVDB", value:"47474");
  script_xref(name:"OSVDB", value:"47753");
  script_xref(name:"OSVDB", value:"47796");
  script_xref(name:"OSVDB", value:"47797");
  script_xref(name:"OSVDB", value:"47798");
  script_xref(name:"OSVDB", value:"47800");
  script_xref(name:"OSVDB", value:"47919");
  script_xref(name:"OSVDB", value:"48158");
  script_xref(name:"OSVDB", value:"49224");
  script_xref(name:"OSVDB", value:"49524");
  script_xref(name:"OSVDB", value:"51142");
  script_xref(name:"OSVDB", value:"51164");
  script_xref(name:"OSVDB", value:"51368");
  script_xref(name:"OSVDB", value:"51477");
  script_xref(name:"OSVDB", value:"52194");
  script_xref(name:"OSVDB", value:"52493");
  script_xref(name:"OSVDB", value:"52747");
  script_xref(name:"OSVDB", value:"52748");
  script_xref(name:"OSVDB", value:"52749");
  script_xref(name:"OSVDB", value:"52963");
  script_xref(name:"OSVDB", value:"53315");
  script_xref(name:"OSVDB", value:"53316");
  script_xref(name:"OSVDB", value:"53317");
  script_xref(name:"OSVDB", value:"53383");
  script_xref(name:"OSVDB", value:"53384");
  script_xref(name:"OSVDB", value:"53385");
  script_xref(name:"OSVDB", value:"53593");
  script_xref(name:"OSVDB", value:"54068");
  script_xref(name:"OSVDB", value:"54069");
  script_xref(name:"OSVDB", value:"54070");
  script_xref(name:"OSVDB", value:"54437");
  script_xref(name:"OSVDB", value:"54438");
  script_xref(name:"OSVDB", value:"54439");
  script_xref(name:"OSVDB", value:"54440");
  script_xref(name:"OSVDB", value:"54441");
  script_xref(name:"OSVDB", value:"54442");
  script_xref(name:"OSVDB", value:"54443");
  script_xref(name:"OSVDB", value:"54444");
  script_xref(name:"OSVDB", value:"54445");
  script_xref(name:"OSVDB", value:"54446");
  script_xref(name:"OSVDB", value:"54447");
  script_xref(name:"OSVDB", value:"54448");
  script_xref(name:"OSVDB", value:"54449");
  script_xref(name:"OSVDB", value:"54450");
  script_xref(name:"OSVDB", value:"54451");
  script_xref(name:"OSVDB", value:"54452");
  script_xref(name:"OSVDB", value:"54453");
  script_xref(name:"OSVDB", value:"54454");
  script_xref(name:"OSVDB", value:"54455");
  script_xref(name:"OSVDB", value:"54461");
  script_xref(name:"OSVDB", value:"54497");
  script_xref(name:"OSVDB", value:"54920");
  script_xref(name:"OSVDB", value:"56273");
  script_xref(name:"OSVDB", value:"56274");

  script_name(english:"Mac OS X < 10.5.7 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

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
      "The remote host is running a version of Mac OS X 10.5 that is older\n",
      "than version 10.5.7. \n",
      "\n",
      "Mac OS X 10.5.7 contains security fixes for the following products :\n",
      "\n",
      "  - Apache\n",
      "  - ATS\n",
      "  - BIND\n",
      "  - CFNetwork\n",
      "  - CoreGraphics\n",
      "  - Cscope\n",
      "  - CUPS\n",
      "  - Disk Images\n",
      "  - enscript\n",
      "  - Flash Player plug-in\n",
      "  - Help Viewer\n",
      "  - iChat\n",
      "  - International Components for Unicode\n",
      "  - IPSec\n",
      "  - Kerberos\n",
      "  - Kernel\n",
      "  - Launch Services\n",
      "  - libxml\n",
      "  - Net-SNMP\n",
      "  - Network Time\n",
      "  - Networking\n",
      "  - OpenSSL\n",
      "  - PHP\n",
      "  - QuickDraw Manager\n",
      "  - ruby\n",
      "  - Safari\n",
      "  - Spotlight\n",
      "  - system_cmds\n",
      "  - telnet\n",
      "  - Terminal\n",
      "  - WebKit\n",
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
    value:"Upgrade to Mac OS X 10.5.7 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os) os = get_kb_item("Host/OS");
if (!os) exit(0);

if (ereg(pattern:"Mac OS X 10\.5\.[0-6]([^0-9]|$)", string:os)) 
  security_hole(0);
