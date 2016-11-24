#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33880);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2008-0120", "CVE-2008-0121", "CVE-2008-1455");
 script_bugtraq_id(30552, 30554, 30579);
 script_xref(name:"OSVDB", value:"47404");
 script_xref(name:"OSVDB", value:"47405");
 script_xref(name:"OSVDB", value:"47406");

 name["english"] = "MS08-051: Vulnerabilities in Microsoft PowerPoint Could Allow Remote Code Execution (949785)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
PowerPoint." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft PowerPoint which is
subject to a flaw which may allow arbitrary code to be run. 

An attacker may use this to execute arbitrary code on this host. 

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.  Then a bug in the font
parsing handler would result in code execution." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for PowerPoint 2000, XP and
2003 :

http://www.microsoft.com/technet/security/bulletin/ms08-051.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the version of PowerPoint.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
port = get_kb_item("SMB/transport");


#
# PowerPoint
#
v = get_kb_item("SMB/Office/PowerPoint/Version");
if ( v ) 
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # PowerPoint 2000 - fixed in 9.0.0.8969
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8969 ) { {
 set_kb_item(name:"SMB/Missing/MS08-051", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # PowerPoint XP - fixed in 10.0.6842.0	
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6842) { {
 set_kb_item(name:"SMB/Missing/MS08-051", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # PowerPoint 2003 - fixed in 11.0.8227.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8227 ) { {
 set_kb_item(name:"SMB/Missing/MS08-051", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^12\..*", string:v))
 {
  # PowerPoint 2007 - fixed in 12.0.6300.5000
   middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6300 ) { {
 set_kb_item(name:"SMB/Missing/MS08-051", value:TRUE);
 hotfix_security_hole();
 }}
 }
}

v = get_kb_item("SMB/Office/PowerPointViewer/Version");
if ( v ) 
{
 if(ereg(pattern:"^11\..*", string:v))
 {
  # PowerPointViewer 2003 - fixed in 11.0.8164.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8164 ) { {
 set_kb_item(name:"SMB/Missing/MS08-051", value:TRUE);
 hotfix_security_hole();
 }}
 }
}
