#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11831);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2003-0664");
 script_bugtraq_id(8533);
 script_xref(name:"IAVA", value:"2002-B-0004");
 script_xref(name:"OSVDB", value:"2506");
 script_xref(name:"OSVDB", value:"10935");
 
 name["english"] = "MS03-035: Word Macros may run automatically (827653)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through VBA." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word that contains a
flaw in its handling of macro command execution.  An attacker may use
this to execute arbitrary code on this host. 

To succeed, the attacker would have to send a rogue Word file to a
user of this computer and have him open it.  Then the macros contained
in the Word file would bypass the security model of Word and be
executed." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office :

http://www.microsoft.com/technet/security/bulletin/ms03-035.mspx" );
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
v = get_kb_item("SMB/Office/Word/Version");
if(!v)exit(0);
if(ereg(pattern:"^10\..*", string:v))
  {
  # Word 2002 - updated in 10.0.5522.0
  middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 5522) {
 set_kb_item(name:"SMB/Missing/MS03-035", value:TRUE);
 hotfix_security_hole();
 }
  }
else if(ereg(pattern:"^9\..*", string:v))
{
 # Word 2000 - fixed in 9.00.00.7924
 sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
 if(sub != v && int(sub) < 7924) {
 set_kb_item(name:"SMB/Missing/MS03-035", value:TRUE);
 hotfix_security_hole();
 }
}
else if(ereg(pattern:"^8\..*", string:v))
{
 # Word 97 - fixed in 8.0.0.8125
 sub =  ereg_replace(pattern:"^8\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
 if(sub != v && int(sub) < 8125) {
 set_kb_item(name:"SMB/Missing/MS03-035", value:TRUE);
 hotfix_security_hole();
 }
}
