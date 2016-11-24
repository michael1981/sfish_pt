#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(32311);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2008-0119");
 script_bugtraq_id(29158);
 script_xref(name:"OSVDB", value:"45033");

 name["english"] = "MS08-027: Vulnerability in Microsoft Publisher Could Allow Remote Code Execution (951208)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Publisher." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Publisher which is
subject to a flaw which may allow arbitrary code to be run. 

An attacker may use this to execute arbitrary code on this host. 

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.  Then a bug in the font
parsing handler would result in code execution." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Publisher 2000, XP, 2003
and 2007 :

http://www.microsoft.com/technet/security/bulletin/ms08-027.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the version of MSPUB.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

port = kb_smb_transport();
if (!is_accessible_share()) exit(0);
  
v = get_kb_item("SMB/Office/Publisher/Version");
if ( v ) 
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Publisher 2000 - fixed in 9.0.8932.0 ? 9.00.00.8931
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8932 ) { {
 set_kb_item(name:"SMB/Missing/MS08-027", value:TRUE);
 hotfix_security_hole();
 }exit(0);}
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Publisher XP - fixed in 10.0.6842.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6842) { {
 set_kb_item(name:"SMB/Missing/MS08-027", value:TRUE);
 hotfix_security_hole();
 }exit(0);}
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # Publisher 2003 - fixed in 11.0.8212.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8212) { {
 set_kb_item(name:"SMB/Missing/MS08-027", value:TRUE);
 hotfix_security_hole();
 }exit(0);}
 }
 else if(ereg(pattern:"^12\..*", string:v))
 {
  # Publisher 2007 - fixed in 12.0.6308.5000
   middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6308) { {
 set_kb_item(name:"SMB/Missing/MS08-027", value:TRUE);
 hotfix_security_hole();
 }exit(0);}
 }
}

programfiles = hotfix_get_officeprogramfilesdir();
if  ( ! programfiles ) exit(0);
if ( 
  hotfix_check_fversion(file:"Ptxt9.dll", path:programfiles +"\Microsoft Office\Office", version:"9.0.0.8929", min_version:"9.0.0.0") == HCF_OLDER  ||
  hotfix_check_fversion(file:"Ptxt9.dll", path:programfiles +"\Microsoft Office\Office10", version:"10.0.6842.0") == HCF_OLDER  ||
  hotfix_check_fversion(file:"Ptxt9.dll", path:programfiles +"\Microsoft Office\Office11", version:"11.0.8212.0") == HCF_OLDER  ||
  hotfix_check_fversion(file:"Ptxt9.dll", path:programfiles +"\Microsoft Office\Office12", version:"12.0.6300.5000") == HCF_OLDER  )
		 {
 set_kb_item(name:"SMB/Missing/MS08-027", value:TRUE);
 hotfix_security_hole();
 }


hotfix_check_fversion_end();
