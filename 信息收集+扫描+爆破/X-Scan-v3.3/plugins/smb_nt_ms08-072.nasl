#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(35071);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2008-4024", "CVE-2008-4025", "CVE-2008-4026", "CVE-2008-4027", "CVE-2008-4030", "CVE-2008-4028", "CVE-2008-4031", "CVE-2008-4837");
 script_bugtraq_id(32579, 32580, 32581, 32583, 32584, 32585, 32594, 32642);
 script_xref(name:"OSVDB", value:"50590");
 script_xref(name:"OSVDB", value:"50591");
 script_xref(name:"OSVDB", value:"50592");
 script_xref(name:"OSVDB", value:"50593");
 script_xref(name:"OSVDB", value:"50595");
 script_xref(name:"OSVDB", value:"50596");
 script_xref(name:"OSVDB", value:"50597");

 script_name(english: "MS08-072: Vulnerabilities in Microsoft Word Could Allow Remote Code Execution (957173)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft Word." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word
which is subject to a flaw which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to 
a user of the remote computer and have it open it. Then a bug in
the word record parsing handler would result in code execution." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Word :

http://www.microsoft.com/technet/security/bulletin/ms08-072.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the version of WinWord.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl");
 exit(0);
}

include("smb_hotfixes_fcheck.inc");

port = get_kb_item("SMB/transport");


#
# Word
#
v = get_kb_item("SMB/Office/Word/Version");
if ( v ) 
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Word 2000 - fixed in 9.0.0.8974
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8974 ) { {
 set_kb_item(name:"SMB/Missing/MS08-072", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Word XP - fixed in 10.0.6850.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6850 ) { {
 set_kb_item(name:"SMB/Missing/MS08-072", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # Word 2003 - fixed in 11.0.8237.0 :
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8237 ) { {
 set_kb_item(name:"SMB/Missing/MS08-072", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^12\..*", string:v))
 {
  # Word 2007 - fixed in 12.0.6331.5000
   middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6331 ) { {
 set_kb_item(name:"SMB/Missing/MS08-072", value:TRUE);
 hotfix_security_hole();
 }}
 }
}

#
# Word Viewer
#
v = get_kb_item("SMB/Office/WordViewer/Version");
if ( v && ereg(pattern:"^11\..*", string:v))
{
  # Word Viewer 2003 - fixed in 11.0.8241.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8241 ) { {
 set_kb_item(name:"SMB/Missing/MS08-072", value:TRUE);
 hotfix_security_hole();
 }}
}
