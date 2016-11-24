#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(26966);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2007-3899");
 script_bugtraq_id(25906);
 script_xref(name:"OSVDB", value:"37632");

 name["english"] = "MS07-060: Vulnerabilities in Microsoft Word Could Allow Remote Code Execution (942695)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Word." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word that may allow
arbitrary code to be run. 

An attacker may use this to execute arbitrary code on this host. 

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.  Then a bug in the font
parsing handler would result in code execution." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Word 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms07-060.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the version of WinWord.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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
  # Word 2000 - fixed in 9.0.0.8965
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8965 ) { {
 set_kb_item(name:"SMB/Missing/MS07-060", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Word XP - fixed in 10.0.6835.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6835) { {
 set_kb_item(name:"SMB/Missing/MS07-060", value:TRUE);
 hotfix_security_hole();
 }}
 }
}
