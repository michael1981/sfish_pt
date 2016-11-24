#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(18024);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2005-0560");
 script_bugtraq_id(13118);
 script_xref(name:"IAVA", value:"2005-A-0010");
 script_xref(name:"OSVDB", value:"15467");

 name["english"] = "MS05-021: Vulnerability in SMTP Could Allow Remote Code Execution (894549)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the SMTP server." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a flaw in its SMTP service which could allow remote
code execution.
Vulnerable services are  Exchange 2003 (Windows 2000) and Exchange 2000.

A public code is available to exploit this vulnerability." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Exchange 2000 and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-021.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks for MS Hotfix 894549";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_nt_server() <= 0 ) exit(0);

version = get_kb_item ("SMB/Exchange/Version");
sp = get_kb_item ("SMB/Exchange/SP");


if ( ! version ) exit(0);

if ( version == 65 )
{
 if (sp && (sp >= 2)) exit (0);

 if (is_accessible_share())
 {
  if (sp)
  {
   if ( hotfix_check_fversion(file:"Xlsasink.dll", version:"6.5.7232.89", path:get_kb_item("SMB/Exchange/Path") + "\bin") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS05-021", value:TRUE);
 hotfix_security_hole();
 }
  }
  else
  {
   if ( hotfix_check_fversion(file:"Xlsasink.dll", version:"6.5.6981.3", path:get_kb_item("SMB/Exchange/Path") + "\bin") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS05-021", value:TRUE);
 hotfix_security_hole();
 }
  }
  hotfix_check_fversion_end(); 
 }
 else
 {
  if ( hotfix_missing(name:"894549") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS05-021", value:TRUE);
 hotfix_security_hole();
 }
 }
 exit (0);
}

if (version == 60)
{
 if (sp && (sp >= 4)) exit (0);

 if (is_accessible_share())
 {
  if ( hotfix_check_fversion(file:"Xlsasink.dll", version:"6.0.6617.52", path:get_kb_item("SMB/Exchange/Path") + "\bin") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS05-021", value:TRUE);
 hotfix_security_hole();
 }
  hotfix_check_fversion_end(); 
 }
 else
 {
  if ( hotfix_missing(name:"894549") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS05-021", value:TRUE);
 hotfix_security_hole();
 }
 }
 exit (0);
}
