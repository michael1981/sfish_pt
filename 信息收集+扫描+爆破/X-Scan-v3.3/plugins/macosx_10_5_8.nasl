#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);

include("compat.inc");

if (description)
{
  script_id(40502);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-0674", "CVE-2008-1372", "CVE-2009-0040", "CVE-2009-0151", "CVE-2009-1235",
                "CVE-2009-1720", "CVE-2009-1721", "CVE-2009-1722", "CVE-2009-1723", "CVE-2009-1726",
                "CVE-2009-1727", "CVE-2009-1728", "CVE-2009-2188", "CVE-2009-2190", "CVE-2009-2191",
                "CVE-2009-2192", "CVE-2009-2193", "CVE-2009-2194");
  script_bugtraq_id(27786, 28286, 33827, 34203, 35838, 36025);
  script_xref(name:"OSVDB", value:"41989");
  script_xref(name:"OSVDB", value:"43425");
  script_xref(name:"OSVDB", value:"53315");
  script_xref(name:"OSVDB", value:"53316");
  script_xref(name:"OSVDB", value:"53317");
  script_xref(name:"OSVDB", value:"53333");
  script_xref(name:"OSVDB", value:"56707");
  script_xref(name:"OSVDB", value:"56708");
  script_xref(name:"OSVDB", value:"56709");

  script_name(english:"Mac OS X < 10.5.8 Multiple Vulnerabilities");
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
      "than version 10.5.8. \n",
      "\n",
      "Mac OS X 10.5.8 contains security fixes for the following products :\n",
      "\n",
      "  - bzip2\n",
      "  - CFNetwork\n",
      "  - ColorSync\n",
      "  - CoreTypes\n",
      "  - Dock\n",
      "  - Image RAW\n",
      "  - ImageIO\n",
      "  - Kernel\n",
      "  - launchd\n",
      "  - Login Window\n",
      "  - MobileMe\n",
      "  - Networking\n",
      "  - XQuery"
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
    value:"Upgrade to Mac OS X 10.5.8 or later."
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
 
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os) os = get_kb_item("Host/OS");
if (!os) exit(1, "The 'Host/OS' KB item is missing.");

if (ereg(pattern:"Mac OS X 10\.5\.[0-7]([^0-9]|$)", string:os)) security_hole(0);
else exit(0, "The host is not affected.");
