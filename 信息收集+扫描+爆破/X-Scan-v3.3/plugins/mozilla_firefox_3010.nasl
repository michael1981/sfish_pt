#
# (C) Tenable Network Security, Inc.


include("compat.inc");

if (description)
{
  script_id(38200);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-1313", "CVE-2009-2061");
  script_bugtraq_id(34743, 35412);
  script_xref(name:"OSVDB", value:"54174");
  script_xref(name:"OSVDB", value:"55133");
  script_xref(name:"Secunia", value:"34866");

  script_name(english:"Firefox < 3.0.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote host is earlier
than 3.0.10.  Such versions have multiple vulnerabilities :

  - An error in function '@nsTextFrame::ClearTextRun()' could 
    corrupt the memory. Successful exploitation of this issue
    may allow arbitrary code execution on the remote system. 
    Note this reportedly only affects 3.0.9. (MFSA 2009-23)

  - The browser processes a 3xx HTTP CONNECT response before
    a successful SSL handshake, which could allow a man-in-
    the-middle attacker to execute arbitrary web script in the
    context of a HTTPS server. (CVE-2009-2061)");

 script_set_attribute(attribute:"see_also", value:"http://research.microsoft.com/apps/pubs/default.aspx?id=79323" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-23.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 3.0.10 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 10)
) security_hole(get_kb_item("SMB/transport"));
