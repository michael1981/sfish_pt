#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25004);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-0002", "CVE-2007-0238", "CVE-2007-1466");
  script_bugtraq_id(23006, 23067);
  script_xref(name:"OSVDB", value:"33315");
  script_xref(name:"OSVDB", value:"33972");

  script_name(english:"OpenOffice < 2.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of OpenOffice"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that may be affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of OpenOffice.org which is older
than version 2.2.  Those versions are reportedly affected by a stack
buffer overflow vulnerability in its handling of StarCalc documents. 
If a remote attacker can trick a user into opening a specially-crafted
StarCalc document, he can execute arbitrary code on the remote host
subject to the user's privileges. 

In addition, versions 2.0 - 2.1 reportedly have a heap buffer overflow
vulnerability that can be triggered when importing a specially-crafted
WordPerfect document, resulting in arbitrary code execution." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-04/0089.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-2.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-0238.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-0239.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenOffice version 2.2 or later." );
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
    if (buildid < 9134) security_hole(get_kb_item("SMB/transport"));
  }
}
