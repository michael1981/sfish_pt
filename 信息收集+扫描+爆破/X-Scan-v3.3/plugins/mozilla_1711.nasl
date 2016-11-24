#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19718);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-2602", "CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703",
                "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707");
  script_bugtraq_id(14526, 14916, 14917, 14918, 14919, 14920, 14921, 14923);
  script_xref(name:"OSVDB", value:"18691");
  script_xref(name:"OSVDB", value:"19643");
  script_xref(name:"OSVDB", value:"19644");
  script_xref(name:"OSVDB", value:"19645");
  script_xref(name:"OSVDB", value:"19646");
  script_xref(name:"OSVDB", value:"19647");
  script_xref(name:"OSVDB", value:"19648");
  script_xref(name:"OSVDB", value:"19649");

  script_name(english:"Mozilla Browser < 1.7.12 Multiple Vulnerabilities");
  script_summary(english:"Checks for Mozilla browser < 1.7.12");
 
 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple vulnerabilities,
including arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"The installed version of Mozilla contains various security issues,
several of which are critical as they can be easily exploited to
execute arbitrary shell code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://security-protocols.com/advisory/sp-x17-advisory.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/idn.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-58.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla 1.7.12 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Version");
  exit(0);
}

#

include("misc_func.inc");


ver = read_version_in_kb("Mozilla/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 7 ||
      (ver[1] == 7 && ver[2] < 12)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
