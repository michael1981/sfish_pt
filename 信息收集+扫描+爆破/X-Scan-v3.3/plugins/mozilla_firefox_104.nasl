#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(18243);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2005-1476", "CVE-2005-1477", "CVE-2005-1531", "CVE-2005-1532");
 script_bugtraq_id(13544, 13641, 13645);
 script_xref(name:"IAVA", value:"2005-T-0014");
 script_xref(name:"OSVDB", value:"16185");
 script_xref(name:"OSVDB", value:"16186");
 script_xref(name:"OSVDB", value:"16576");
 script_xref(name:"OSVDB", value:"16605");

 script_name(english:"Firefox < 1.0.4 Multiple Vulnerabilities");
 script_summary(english:"Determines the version of Firefox");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote Windows host contains a web browser that is affected by\n",
     "multiple vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The installed version of Firefox is earlier than 1.0.4.  Such\n",
     "versions have multiple vulnerabilities that may allow arbitrary\n",
     "code execution."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-42.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-43.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-44.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Firefox 1.0.4 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Firefox/Version");
 exit(0);
}

#

include("misc_func.inc");


ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] == 0 && ver[2] < 4)
) security_hole(get_kb_item("SMB/transport"));
