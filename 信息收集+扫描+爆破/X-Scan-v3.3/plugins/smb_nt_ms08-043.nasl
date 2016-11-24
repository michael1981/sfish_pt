#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33872);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2008-3003", "CVE-2008-3004", "CVE-2008-3005", "CVE-2008-3006");
 script_bugtraq_id(30638, 30639, 30640, 30641);
 script_xref(name:"OSVDB", value:"47407");
 script_xref(name:"OSVDB", value:"47408");
 script_xref(name:"OSVDB", value:"47409");
 script_xref(name:"OSVDB", value:"47410");

 name["english"] = "MS08-043: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (954066)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Excel." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Excel which is
subject to various flaws which may allow arbitrary code to be run. 

An attacker may use this to execute arbitrary code on this host. 

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with Microsoft Excel." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2000, XP, 2003 and
2007 :

http://www.microsoft.com/technet/security/bulletin/ms08-043.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the version of Excel.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl");
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
port = get_kb_item("SMB/transport");



#
# Excel
#
v = get_kb_item("SMB/Office/Excel/Version");
if ( v ) 
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Excel 2000 - fixed in 9.0.0.8971
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8971 ) { {
 set_kb_item(name:"SMB/Missing/MS08-043", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Excel XP - fixed in 10.0.6845.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6845 ) { {
 set_kb_item(name:"SMB/Missing/MS08-043", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # Excel 2003 - fixed in 11.0.8220.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8220 ) { {
 set_kb_item(name:"SMB/Missing/MS08-043", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^12\..*", string:v))
 {
  # Excel 2007 - fixed in 12.0.6323.5000
   middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
   low =  ereg_replace(pattern:"^12\.0\.[0-9]*\.([0-9]*)$", string:v, replace:"\1");
  if(middle != v && ( int(middle) < 6323 ) ) { {
 set_kb_item(name:"SMB/Missing/MS08-043", value:TRUE);
 hotfix_security_hole();
 }}
 }
}


#
# Excel Viever
#
v = get_kb_item("SMB/Office/ExcelViewer/Version");
if (v && ereg(pattern:"^11\..*", string:v))
{
 # Excel Viwever 2003 - fixed in 11.0.8220.0
 middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
 if(middle != v && int(middle) < 8220 ) { {
 set_kb_item(name:"SMB/Missing/MS08-043", value:TRUE);
 hotfix_security_hole();
 }}
}
else if (v && ereg(pattern:"^12\..*", string:v))
{
 # Excel Viwever 2003 - fixed in 12.0.6324.5000
 middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
 if(middle != v && int(middle) < 6324) { {
 set_kb_item(name:"SMB/Missing/MS08-043", value:TRUE);
 hotfix_security_hole();
 }}
}
