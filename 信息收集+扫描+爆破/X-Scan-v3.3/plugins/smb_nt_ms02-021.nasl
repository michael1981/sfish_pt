#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11325);
 script_version("$Revision: 1.24 $");

 script_cve_id("CVE-2002-1056");
 script_bugtraq_id(4397);
 script_xref(name:"OSVDB", value:"2061");
 
 script_name(english:"MS02-021: Word Mail Reply Arbitrary Script Execution (321804)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Word." );
 script_set_attribute(attribute:"description", value:
"Outlook 2000 and 2002 provide the option to use Microsoft Word as the
e-mail editor when creating and editing e-mail in RTF or HTML. 

There is a flaw in some versions of Word which may allow an attacker
to execute arbitrary code when the user replies to a specially formed
message using Word. 

An attacker may use this flaw to execute arbitrary code on this host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2000 and 2002 :

http://www.microsoft.com/technet/security/bulletin/ms02-021.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines the version of WinWord.exe");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_nt_ms02-031.nasl");
 script_require_keys("SMB/Office/Word/Version");
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
v = get_kb_item("SMB/Office/Word/Version");
port = kb_smb_transport();

if(strlen(v))
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Word 2000 - patched in WinWord 9.0.6328
  middle =  ereg_replace(pattern:"^9\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  minor =   ereg_replace(pattern:"^9\.[0-9]*\.([0-9]*)$", string:v, replace:"\1");
  if(middle == 0 && minor < 6328) {
 set_kb_item(name:"SMB/Missing/MS02-021", value:TRUE);
 hotfix_security_hole();
 }
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Word 2002 - updated in 10.0.4009.3501
  
  middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  minor  =  ereg_replace(pattern:"^10\.0\.[0-9]*\.([0-9]*)$", string:v, replace:"\1");
  if(middle < 4009) {
 set_kb_item(name:"SMB/Missing/MS02-021", value:TRUE);
 hotfix_security_hole();
 }
  else if(middle == 4009 && minor < 3501) {
 set_kb_item(name:"SMB/Missing/MS02-021", value:TRUE);
 hotfix_security_hole();
 }
 }
}
