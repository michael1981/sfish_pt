#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25842);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-3844", "CVE-2007-3845", "CVE-2007-4041");
  script_bugtraq_id(25053, 25142);
  script_xref(name:"OSVDB", value:"38026");
  script_xref(name:"OSVDB", value:"38031");
  script_xref(name:"OSVDB", value:"41090");
  script_xref(name:"OSVDB", value:"41188");

  script_name(english:"SeaMonkey < 1.1.4");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey allows unescaped URIs to be passed to
external programs, which may lead to execution of arbitrary code on the
affected host subject to the user's privileges, and could also allow
privilege escalation attacks against addons that create 'about:blank'
windows and populate them in certain ways." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-23.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-26.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-27.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.1.4 or later." );
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
      (ver[1] == 1 && ver[2] < 4)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
