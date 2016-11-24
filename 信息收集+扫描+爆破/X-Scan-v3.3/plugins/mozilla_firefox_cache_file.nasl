#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14197);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2004-0760");
 script_bugtraq_id(10709);
 script_xref(name:"OSVDB", value:"8307");

 script_name(english:"Firefox < 0.9.3 Null Character MIME Type Spoofing Arbitrary Code Execution");
 script_summary(english:"Determines the version of Firefox");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote Windows host contains a web browser that has a code\n",
     "execution vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The installed version of Firefox is earlier than 0.9.3.  Such\n",
     "versions may allow arbitrary code execution.\n\n",
     "The security vulnerability is due to the fact that Firefox stores\n",
     "cached HTML documents with a known file name, and to the fact that\n",
     "it's possible to force Firefox to open cached files as HTML documents\n",
     "by appending a NULL byte after the file name.\n\n",
     "A remote attacker may combine these two flaws to execute arbitrary\n",
     "code on the remote host."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Firefox 0.9.3 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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
  ver[0] == 0 && 
  (
    ver[1] < 9 ||
    (ver[1] == 9 && ver[2] < 2)
  )
) security_hole(get_kb_item("SMB/transport"));
