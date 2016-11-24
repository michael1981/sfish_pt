#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25765);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-3734", "CVE-2007-3735");
  script_bugtraq_id(24946);
  script_xref(name:"OSVDB", value:"38000");
  script_xref(name:"OSVDB", value:"38001");

  script_name(english:"SeaMonkey < 1.1.3");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey contains various security issues
which may cause the application to crash or lead to execution of
arbitrary code on the affected host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-18.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.1.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}


include("misc_func.inc");


ver = read_version_in_kb("SeaMonkey/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 && 
    (
      ver[1] == 0 ||
      (ver[1] == 1 && ver[2] < 3)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
