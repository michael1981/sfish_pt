#
# (C) Tenable Network Security, Inc.
#

# MS01-011 was superceded by MS01-036

include("compat.inc");

if(description)
{
 script_id(10619);
 script_version ("$Revision: 1.29 $");

 script_cve_id("CVE-2001-0502");
 script_bugtraq_id(2929);
 script_xref(name:"OSVDB", value:"515");
 
 script_name(english:"MS01-011 / MS01-036: LDAP over SSL Arbitrary User Password Modification (287397 / 299687)");
 script_summary(english:"Determines whether the hotfix Q299687 is installed"); 

 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "A bug in Windows 2000 may allow an attacker to change the password of\n",
   "a third party user."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote version of Windows 2000 contains a bug in its LDAP\n",
   "implementation that fails to validate the permissions of a user\n",
   "requesting to change the password of a third party user. \n",
   "\n",
   "An attacker may exploit this vulnerability to gain unauthorized access\n",
   "to the remote host."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "http://www.microsoft.com/technet/security/bulletin/ms01-011.mspx\n",
   "http://www.microsoft.com/technet/security/bulletin/ms01-036.mspx\n"
  )
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

if ( hotfix_check_domain_controler() <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:3) <= 0 ) exit(0);
if ( hotfix_missing(name:"SP2SPR1") > 0 && hotfix_missing(name:"Q299687") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS01-036", value:TRUE);
 hotfix_security_hole();
 }
