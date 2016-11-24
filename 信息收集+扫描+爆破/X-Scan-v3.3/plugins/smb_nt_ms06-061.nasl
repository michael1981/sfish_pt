#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22534);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2006-4685", "CVE-2006-4686");
 script_bugtraq_id(20338, 20339);
 script_xref(name:"OSVDB", value:"29425");
 script_xref(name:"OSVDB", value:"29426");

 name["english"] = "MS06-061: Vulnerabilities in Microsoft XML Core Services Could Allow Remote Code Execution (924191)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web or
email client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that contains a flaw
in the Windows XML Core Services.. 

An attacker may be able to execute arbitrary code on the remote host
by constructing a malicious script and enticing a victim to visit a
web site or view a specially-crafted email message." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/Bulletin/MS06-061.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 924191";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) > 0 ) 
{
 if (is_accessible_share())
 {
  if ( ( hotfix_check_fversion(file:"system32\Msxml3.dll", version:"8.70.1113.0") == HCF_OLDER ) ||
       ( hotfix_check_fversion(file:"system32\Msxml4.dll", version:"4.20.9839.0") == HCF_OLDER ) ||
       ( hotfix_check_fversion(file:"system32\Msxml5.dll", version:"5.10.2930.0") == HCF_OLDER ) ||
       ( hotfix_check_fversion(file:"system32\Msxml6.dll", version:"6.0.3888.0") == HCF_OLDER ) )
 {
 set_kb_item(name:"SMB/Missing/MS06-061", value:TRUE);
 hotfix_security_hole();
 }
 
  hotfix_check_fversion_end(); 
 }
}


office_version = hotfix_check_office_version ();
if ( !office_version )
  exit(0);

rootfile = hotfix_get_commonfilesdir();
if ( ! rootfile )
  exit(0);

if ( "11.0" >!< office_version )
  exit (0);

if (!is_accessible_share())
  exit (0);

if ( hotfix_check_fversion(path:rootfile, file:"\Microsoft Shared\Office11\msxml5.dll", version:"5.10.2930.0") == HCF_OLDER )
 {
 set_kb_item(name:"SMB/Missing/MS06-061", value:TRUE);
 hotfix_security_hole();
 }
