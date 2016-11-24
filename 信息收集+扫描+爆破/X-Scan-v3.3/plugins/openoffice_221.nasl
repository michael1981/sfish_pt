#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25552);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-0245");
  script_bugtraq_id(24450);
  script_xref(name:"OSVDB", value:"35378");

  script_name(english:"OpenOffice RTF Parser prtdata Tag Buffer Overflow");
  script_summary(english:"Checks version of OpenOffice"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by a buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of OpenOffice.org that is
affected by a heap buffer overflow in its RTF document parser that is
triggered when parsing 'prtdata' tags.  If a remote attacker can trick
a user into opening a specially-crafted RTF document, he can execute
arbitrary code on the remote host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-06/0170.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/issues/show_bug.cgi?id=77214" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2007-0245.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenOffice version 2.2.1 or later." );
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
    if (buildid < 9161) security_hole(get_kb_item("SMB/transport"));
  }
}
