#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(24337);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2006-1311");
 script_bugtraq_id(21876);
 script_xref(name:"OSVDB", value:"31886");

 name["english"] = "MS07-013: Vulnerability in Microsoft RichEdit Could Allow Remote Code Execution (918118)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the RichEdit
component provided with Microsoft Windows and Microsoft Office" );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Windows and/or Microsoft
Office which has a vulnerability in the RichEdit component which could 
be abused by an attacker to execute arbitrary code on the remote host.

To exploit this vulnerability, an attacker would need to spend a specially
crafted RTF file to a user on the remote host and lure him into opening it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/Bulletin/MS07-013.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 918118";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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



if (is_accessible_share())
{
 #
 # Windows
 #
 if ( hotfix_is_vulnerable (os:"5.2", sp:1, file:"Riched20.dll", version:"5.31.23.1226", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:0, file:"Riched20.dll", version:"5.31.23.1224", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Riched20.dll", version:"5.30.23.1228", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Riched20.dll", version:"5.30.23.1227", dir:"\system32") )
	e ++;
 
 if ( office_version = hotfix_check_office_version () )
 {
  rootfile = hotfix_get_officecommonfilesdir();
  if ( "11.0" >< office_version )  # Office 2003
  {
    if ( hotfix_check_fversion(path:rootfile, file:"\Microsoft Shared\Office11\Riched20.dll", version:"5.50.99.2014") == HCF_OLDER ) e ++;
  }
  if ( "10.0" >< office_version )  # Office XP
  {
    if ( hotfix_check_fversion(path:rootfile, file:"\Microsoft Shared\Office10\Riched20.dll", version:"5.40.11.2220") == HCF_OLDER ) e ++;
  }

 }


 if ( e ) {
 set_kb_item(name:"SMB/Missing/MS07-013", value:TRUE);
 hotfix_security_hole();
 }

 hotfix_check_fversion_end();
 exit (0);
}
