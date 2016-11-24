#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(40946);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2009-1862", "CVE-2009-1863", "CVE-2009-1864", "CVE-2009-1865", "CVE-2009-1866",
                "CVE-2009-1867", "CVE-2009-1868", "CVE-2009-1869", "CVE-2009-1870");
  script_bugtraq_id(35759, 36349);
  script_xref(name:"OSVDB", value:"56282");
  script_xref(name:"OSVDB", value:"56771");
  script_xref(name:"OSVDB", value:"56772");
  script_xref(name:"OSVDB", value:"56773");
  script_xref(name:"OSVDB", value:"56774");
  script_xref(name:"OSVDB", value:"56775");
  script_xref(name:"OSVDB", value:"56776");
  script_xref(name:"OSVDB", value:"56777");
  script_xref(name:"OSVDB", value:"56778");

  script_name(english:"Mac OS X < 10.6.1 Multiple Vulnerabilities");
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
      "The remote host is running a version of Mac OS X 10.6 that is older\n",
      "than version 10.6.1. \n",
      "\n",
      "Mac OS X 10.6.1 contains security fixes for the following product :\n",
      "\n",
      "  - Flash Player plug-in"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3864"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/sep/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17867"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mac OS X 10.6.1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/09/10"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/11"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os) {
  os = get_kb_item("Host/OS");
  c = get_kb_item("Host/OS/Confidence");
  if ( isnull(os) || c <= 70 ) exit(0);
}
if (!os) exit(1, "The 'Host/OS' KB item is missing.");

if (ereg(pattern:"Mac OS X 10\.6($|\.0)", string:os)) security_hole(0);
else exit(0, "The host is not affected.");
