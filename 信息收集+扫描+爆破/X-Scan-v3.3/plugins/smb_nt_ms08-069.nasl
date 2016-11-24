#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34744);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2007-0099", "CVE-2008-4029", "CVE-2008-4033");
 script_bugtraq_id(21872, 32155, 32204);
 script_xref(name:"OSVDB", value:"32627");
 script_xref(name:"OSVDB", value:"49926");
 script_xref(name:"OSVDB", value:"50279");

 name["english"] = "MS08-069: Vulnerabilities in Microsoft XML Core Services Could Allow Remote Code Execution (955218)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web or
email client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows which contains a flaw
in the Windows XML Core Services..

An attacker may be able to execute arbitrary code on the remote host
by constructing a malicious script and enticing a victim to visit a
web site or view a specially-crafted email message." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008:

http://www.microsoft.com/technet/security/Bulletin/MS08-069.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 955218";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (is_accessible_share())
{
  if ( ( hotfix_check_fversion(file:"system32\Msxml3.dll", version:"8.100.1048.0") == HCF_OLDER ) ||
       ( hotfix_check_fversion(file:"system32\Msxml4.dll", version:"4.20.9870.0") == HCF_OLDER ) ||
       ( hotfix_check_fversion(file:"system32\Msxml5.dll", version:"5.20.1087.0") == HCF_OLDER ) ||
       ( hotfix_check_fversion(file:"system32\Msxml6.dll", version:"6.20.1099.0") == HCF_OLDER ) )
  {
 {
 set_kb_item(name:"SMB/Missing/MS08-069", value:TRUE);
 hotfix_security_hole();
 }
    hotfix_check_fversion_end(); 
    exit(0);
  }

 hotfix_check_fversion_end(); 
 

 office_version = hotfix_check_office_version ();
 if ( !office_version )
  exit(0);

 rootfile = hotfix_get_officecommonfilesdir();
 if ( ! rootfile )
  exit(0);

 if ( "11.0" >!< office_version && "12.0" >!< office_version)
  exit (0);

 if (!is_accessible_share())
  exit (0);

 if ( hotfix_check_fversion(path:rootfile, file:"\Microsoft Shared\Office11\msxml5.dll", version:"5.20.1087.0") == HCF_OLDER )
 {
 set_kb_item(name:"SMB/Missing/MS08-069", value:TRUE);
 hotfix_security_hole();
 }

 hotfix_check_fversion_end(); 
}
