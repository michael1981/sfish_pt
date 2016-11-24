#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21609);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-1649");
  script_bugtraq_id(17374);
  script_xref(name:"OSVDB", value:"24393");

  script_name(english:"NOD32 Antivirus Local File Creation");
  script_summary(english:"Checks version number of NOD32");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is subject to a
local privilege escalation attack." );
 script_set_attribute(attribute:"description", value:
"The installed version of NOD32 reportedly allows a local user to
restore a malicious file from NOD32's quarantine to an arbitrary
directory to which the user otherwise has only read access.  A local
user can exploit this issue to gain admin/system privilege on the
affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/429892/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to NOD32 version 2.51.26 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("nod32_installed.nasl");
  script_require_keys("Antivirus/NOD32/version");
  exit(0);
}


ver = get_kb_item("Antivirus/NOD32/version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
if (
  int(iver[0]) < 2 ||
  (
    int(iver[0]) == 2 &&
    (
      int(iver[1]) < 51 ||
      (int(iver[1]) == 51 && int(iver[2]) < 26)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
