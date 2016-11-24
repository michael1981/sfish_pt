#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26068);
  script_version("$Revision: 1.4 $");
  script_cve_id("CVE-2006-4965");
  script_xref(name:"OSVDB", value:"29064");

  script_name(english:"Firefox < 2.0.0.7 Apple QuickTime Plug-In .qtl File qtnext Field Cross-context Scripting");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that may allow
arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox may allow a remote attacker to run
script commands subject to the user's privileges via 'qtnext'
attributes in QuickTime Media-Link files. 

Note that this issue can be exploited even if support for JavaScript
in the browser has been disabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-28.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 2 ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 7)
) security_hole(get_kb_item("SMB/transport"));
