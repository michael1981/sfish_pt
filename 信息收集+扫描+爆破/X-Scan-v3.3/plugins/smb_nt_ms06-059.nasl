#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22532);
 script_version("$Revision: 1.11 $");

 script_cve_id(
  "CVE-2006-2387", 
  "CVE-2006-3431", 
  "CVE-2006-3867", 
  "CVE-2006-3875"
 );
 script_bugtraq_id(18872, 20344, 20345, 20391);
 script_xref(name:"OSVDB", value:"27053");
 script_xref(name:"OSVDB", value:"29443");
 script_xref(name:"OSVDB", value:"29444");
 script_xref(name:"OSVDB", value:"29445");

 name["english"] = "MS06-059: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (924164)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Excel." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Excel that may allow
arbitrary code to be run. 

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with Microsoft Excel." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-059.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the version of Excel.exe";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl");
 exit(0);
}

include("smb_func.inc");
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
  # Excel 2000 - fixed in 9.00.00.8950
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8950 ) { {
 set_kb_item(name:"SMB/Missing/MS06-059", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Excel XP - fixed in 10.0.6816.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6816) { {
 set_kb_item(name:"SMB/Missing/MS06-059", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # Excel 2003 - fixed in 11.0.8104.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8104) { {
 set_kb_item(name:"SMB/Missing/MS06-059", value:TRUE);
 hotfix_security_hole();
 }}
 }
}

