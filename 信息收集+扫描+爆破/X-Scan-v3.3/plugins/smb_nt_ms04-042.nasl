#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15965);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-0899", "CVE-2004-0900");
 script_bugtraq_id(11919, 11920);
 script_xref(name:"IAVA", value:"2004-t-0041");
 script_xref(name:"OSVDB", value:"12371");
 script_xref(name:"OSVDB", value:"12377");

 script_name(english:"MS04-042: Windows NT Multiple DHCP Vulnerabilities (885249)");
 script_summary(english:"Checks version of Dhcpssvc.dll");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host via the DHCP\n",
   "service."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host has the Windows DHCP server installed. \n",
   "\n",
   "There is a flaw in the remote version of this server that may allow an\n",
   "attacker to execute arbitrary code on the remote host with SYSTEM\n",
   "privileges."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows NT :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms04-042.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_nt_server() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_check_dhcpserver_installed() <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"4.0", file:"Dhcpssvc.dll", version:"4.0.1381.7304", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-042", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"885249") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS04-042", value:TRUE);
 hotfix_security_hole();
 }
