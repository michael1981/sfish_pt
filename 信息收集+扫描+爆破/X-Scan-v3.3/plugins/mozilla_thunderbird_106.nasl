#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(19269);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261");
 script_bugtraq_id(14242);
 script_xref(name:"OSVDB", value:"7296");
 script_xref(name:"OSVDB", value:"17964");
 script_xref(name:"OSVDB", value:"17942");

 script_name(english:"Mozilla Thunderbird < 1.0.6 Multiple Vulnerabilities");
 script_summary(english:"Determines the version of Mozilla Thunderbird");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote Windows host contains a mail client that is affected by\n",
     "multiple vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The installed version of Mozilla Thunderbird is affected by\n",
     "multiple vulnerabilities, at least one of which may allow a remote\n",
     "attacker to execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/known-vulnerabilities/thunderbird10.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Mozilla Thunderbird 1.0.6 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Thunderbird/Version");
 exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Thunderbird/Version");
if (isnull(ver)) exit(0);

# nb: 1.0.5 is NOT vulnerable but is "buggy" so we should not advise anyone
# to use it (but we don't flag it either)
if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] == 0 && ver[2] < 6)
) security_hole(get_kb_item("SMB/transport"));
