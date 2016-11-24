#
# (C) Tenable Network Security
#
# Ref: http://www.microsoft.com/technet/security/bulletin/ms03-050.mspx


include("compat.inc");

if(description)
{
 script_id(11920);
 script_bugtraq_id(8835, 9010);
 script_cve_id("CVE-2003-0820", "CVE-2003-0821");
 script_xref(name:"OSVDB", value:"2801");
 
 script_version("$Revision: 1.19 $");

 name["english"] = "MS03-050: Word and/or Excel may allow arbitrary code to run (831527)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Office." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word and/or Microsoft Excel
which are subject to a flaw which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue word or excel
file to the owner of this computer and have it open it. Then the
macros contained in the word file would bypass the security model
of word, and would be executed." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 97, 2000 and 2002 :

http://www.microsoft.com/technet/security/bulletin/ms03-050.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the version of WinWord.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl");
 script_require_keys("SMB/Office/Word/Version");
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
port = get_kb_item("SMB/transport");

v = get_kb_item("SMB/Office/Excel/Version");
if ( v )
{
 if( ereg(pattern:"^8\.0", string:v) )
 {
  # Excel 97 - fixed in 8.0.1.9904
  if( ereg(pattern:"^8\.0*0\.0*0\.", string:v) )
  {
 {
 set_kb_item(name:"SMB/Missing/MS03-050", value:TRUE);
 hotfix_security_hole();
 }
   exit(0);
  }
  last = ereg_replace(pattern:"^8\.0*0\.0*1\.([0-9]*)", string:v, replace:"\1");
  if ( int(last) < 9904 ) { {
 set_kb_item(name:"SMB/Missing/MS03-050", value:TRUE);
 hotfix_security_hole();
 }}
 }
 
 if ( ereg(pattern:"^9\.", string:v) )
 {
  # Excel 2000 - fixed in 9.0.08216
  last = ereg_replace(pattern:"^9\.0*0\.0*0\.(.*)", string:v, replace:"\1");
  if ( int(last) < 8216 ) { {
 set_kb_item(name:"SMB/Missing/MS03-050", value:TRUE);
 hotfix_security_hole();
 }}
 }
 
 if ( ereg(pattern:"^10\.", string:v ) )
 {
  # Excel 2002 - fixed in 10.0.5815.0
  middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 5815){ {
 set_kb_item(name:"SMB/Missing/MS03-050", value:TRUE);
 hotfix_security_hole();
 }}
 }
}

v = get_kb_item("SMB/Office/Word/Version");
if(!v)exit(0);
if(ereg(pattern:"^10\..*", string:v))
  {
  # Word 2002 - updated in 10.0.5815.0
  middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 5815) {
 set_kb_item(name:"SMB/Missing/MS03-050", value:TRUE);
 hotfix_security_hole();
 }
  }
else if(ereg(pattern:"^9\..*", string:v))
{
 # Word 2000 - fixed in 9.00.00.8216
 sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
 if(sub != v && int(sub) < 8216) {
 set_kb_item(name:"SMB/Missing/MS03-050", value:TRUE);
 hotfix_security_hole();
 }
}
else if(ereg(pattern:"^9\..*", string:v))
{
 # Word 97 - fixed in 8.0.0.9716
 sub =  ereg_replace(pattern:"^8\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
 if(sub != v && int(sub) < 9716) {
 set_kb_item(name:"SMB/Missing/MS03-050", value:TRUE);
 hotfix_security_hole();
 }
}
