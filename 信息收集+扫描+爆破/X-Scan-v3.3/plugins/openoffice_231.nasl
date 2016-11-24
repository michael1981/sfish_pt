#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29218);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-4575");
  script_bugtraq_id(26703);
  script_xref(name:"OSVDB", value:"40548");

  script_name(english:"OpenOffice < 2.3.1 Database HSQLDB Database Document Handling Arbitrary Java Code Execution");
  script_summary(english:"Checks version of OpenOffice"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that allows execution of
arbitrary code." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of OpenOffice.org that contains a
potential arbitrary code execution vulnerability in its HSQLDB
database engine.  If a remote attacker can trick a user into opening a
specially-crafted database, he may be able to leverage this issue to
execute arbitrary static Java code on the remote host subject to the
user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-4575.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenOffice version 2.3.1 or later." );
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
    if (buildid > 8950 && buildid < 9238) security_hole(get_kb_item("SMB/transport"));
  }
}
