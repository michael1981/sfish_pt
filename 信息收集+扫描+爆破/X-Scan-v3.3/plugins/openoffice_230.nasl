#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26064);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-2834");
  script_bugtraq_id(25690);
  script_xref(name:"OSVDB", value:"40546");

  script_name(english:"OpenOffice < 2.3 TIFF Parser Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks version of OpenOffice"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by multiple
buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of OpenOffice.org that is
affected by multiple integer overflows in its TIFF document parser
that can be triggered when parsing tags in TIFF directory entries.  If
a remote attacker can trick a user into opening a specially-crafted
TIFF document, he may be able to leverage this issue to execute
arbitrary code on the remote host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=593" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/479759/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-2834.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenOffice version 2.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("SMB/OpenOffice/Build");

  exit(0);
}


build = get_kb_item("SMB/OpenOffice/Build");
if (build)
{
  matches = eregmatch(string:build, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");
  if (!isnull(matches))
  {
    buildid = int(matches[2]);
    if (buildid < 9221) security_hole(get_kb_item("SMB/transport"));
  }
}
