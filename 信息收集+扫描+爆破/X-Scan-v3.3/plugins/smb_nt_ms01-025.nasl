#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(10668);
 script_version ("$Revision: 1.30 $");

 script_cve_id("CVE-2001-0244", "CVE-2001-0245");
 script_bugtraq_id(2709);
 script_xref(name:"OSVDB", value:"553");
 script_xref(name:"OSVDB", value:"1820");
 
 script_name(english:"MS01-025: Index Server Multiple Vulnerabilities (294472 / 296185)");
 script_summary(english:"Determines whether the hotfixes Q294472 and Q296185 are installed");

 script_set_attribute(
  attribute:"synopsis",
  value:"Arbitrary code can be executed on the remote host."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The hotfix for the 'Malformed request to index server' problem has not\n",
   "been applied. \n",
   "\n",
   "This vulnerability can allow an attacker to execute arbitrary code on\n",
   "the remote host."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:"http://www.microsoft.com/technet/security/bulletin/ms01-025.mspx"
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

#

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7, win2k:3) <= 0 ) exit(0);

if ( hotfix_missing(name:"Q299444") > 0 && 
     hotfix_missing(name:"Q296185") > 0 && 
     hotfix_missing(name:"Q294472") > 0 &&
     hotfix_missing(name:"SP2SRP1") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS01-025", value:TRUE);
 hotfix_security_hole();
 }

