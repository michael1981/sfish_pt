#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(21784);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-3117", "CVE-2006-2198", "CVE-2006-2199");
  script_bugtraq_id(18737, 18738, 18739);
  script_xref(name:"OSVDB", value:"26939");
  script_xref(name:"OSVDB", value:"26940");
  script_xref(name:"OSVDB", value:"26941");
  script_xref(name:"OSVDB", value:"26942");
  script_xref(name:"OSVDB", value:"26943");
  script_xref(name:"OSVDB", value:"26944");
  script_xref(name:"OSVDB", value:"26945");

  script_name(english:"OpenOffice.org < 2.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks for the version of OpenOffice.org");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through OpenOffice.org." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of OpenOffice.org which is older than 
version 2.0.3.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of the 
remote computer and have him open it. The file could be crafted in such a
way that it could exploit a buffer overflow in OpenOffice.org's XML parser,
or by containing rogue macros." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenOffice.org 2.0.3 or newer." );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2006-2199.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2006-2198.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2006-3117.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("openoffice_installed.nasl");
  script_require_keys("SMB/OpenOffice/Build");
  exit(0);
}

#

build = get_kb_item("SMB/OpenOffice/Build");
if (build)
{
  matches = eregmatch(string:build, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");
  if (!isnull(matches))
  {
    buildid = int(matches[2]);
    if (buildid < 9044) security_hole(get_kb_item("SMB/transport"));
  }
}
