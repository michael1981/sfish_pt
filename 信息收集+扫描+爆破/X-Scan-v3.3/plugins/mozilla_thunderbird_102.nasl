#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(17605);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2005-0399");
 script_bugtraq_id(12881);
 script_xref(name:"OSVDB", value:"14937");

 name["english"] = 

 script_name(english:"Mozilla Thunderbird < 1.0.2 Browser GIF Processing Overflow ");
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
     "The installed version of Thunderbird is affected by multiple\n",
     "vulnerabilities.  A remote attacker could exploit these issues\n",
     "to execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-17.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-18.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-21.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-25.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/security/announce/2005/mfsa2005-30.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Thunderbird 1.0.2 or later."
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

if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] == 0 && ver[2] < 2)
) security_hole(get_kb_item("SMB/transport"));
