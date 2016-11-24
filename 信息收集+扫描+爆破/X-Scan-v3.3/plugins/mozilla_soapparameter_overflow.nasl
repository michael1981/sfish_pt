#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(14192);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2004-0722");
 script_bugtraq_id(10843);
 script_xref(name:"OSVDB", value:"8281");

 script_name(english:"Mozilla SOAPParameter Object Constructor Overlow");
 script_summary(english:"Determines the version of Mozilla");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote Windows host contains a web browser that is affected by\n",
     "an integer overflow vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The Mozilla web browser is installed on the remote host.\n\n",
     "The remote version of this software has an integer overflow\n",
     "vulnerability in the SOAPParameter object constructor. This could\n",
     "result in arbitrary code execution.\n\n",
     "A remote attacker could exploit this flaw by tricking a user into\n",
     "viewing a maliciously crafted web page."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Mozilla 1.7.1 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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
      (ver[1] == 7 && ver[2] < 1)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
