#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(21078);
 script_version("$Revision: 1.13 $");

 script_cve_id(
  "CVE-2005-4131", 
  "CVE-2006-0028", 
  "CVE-2006-0029", 
  "CVE-2006-0030", 
  "CVE-2006-0031", 
  "CVE-2006-0009"
 );
 script_bugtraq_id(15926, 16181, 17000, 17091, 17100, 17101, 17108);
 script_xref(name:"OSVDB", value:"21568");
 script_xref(name:"OSVDB", value:"23899");
 script_xref(name:"OSVDB", value:"23900");
 script_xref(name:"OSVDB", value:"23901");
 script_xref(name:"OSVDB", value:"23902");
 script_xref(name:"OSVDB", value:"23903");

 name["english"] = "MS06-012: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (905413)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office that may
allow arbitrary code to be run. 

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have him open it.  Then a bug in the font
parsing handler would result in code execution." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Word 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-012.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the version of WinWord.exe / Excel.exe";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
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
# Word
#
v = get_kb_item("SMB/Office/Word/Version");
if ( v ) 
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Word 2000 - fixed in 9.00.00.8939
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8939 ) { {
 set_kb_item(name:"SMB/Missing/MS06-012", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Word XP - fixed in 10.0.6775.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6775) { {
 set_kb_item(name:"SMB/Missing/MS06-012", value:TRUE);
 hotfix_security_hole();
 }}
 }
}

#
# Excel
#
v = get_kb_item("SMB/Office/Excel/Version");
if ( v ) 
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Excel 2000 - fixed in 9.00.00.8938
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8938 ) { {
 set_kb_item(name:"SMB/Missing/MS06-012", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Excel XP - fixed in 10.0.6789.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6789 ) { {
 set_kb_item(name:"SMB/Missing/MS06-012", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # Excel 2003 - fixed in 11.0.8012.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8012) { {
 set_kb_item(name:"SMB/Missing/MS06-012", value:TRUE);
 hotfix_security_hole();
 }}
 }
}

