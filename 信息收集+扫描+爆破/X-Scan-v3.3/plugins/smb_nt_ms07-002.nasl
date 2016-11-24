#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(23998);
 script_cve_id("CVE-2007-0027", "CVE-2007-0028", "CVE-2007-0029", "CVE-2007-0030", "CVE-2007-0031");
 script_bugtraq_id(21856, 21877, 21922, 21925, 21952);
 script_xref(name:"OSVDB", value:"31249");
 script_xref(name:"OSVDB", value:"31255");
 script_xref(name:"OSVDB", value:"31256");
 script_xref(name:"OSVDB", value:"31257");
 script_xref(name:"OSVDB", value:"31258");
 script_version("$Revision: 1.11 $");

 name["english"] = "MS07-002: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (927198)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft Excel" );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Excel
which is subject to various flaws which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to 
a user of the remote computer and have it open it with
Microsoft Excel." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms07-002.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the version of Excel.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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
  # Excel 2000 - fixed in 9.00.00.8955
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8955 ) { {
 set_kb_item(name:"SMB/Missing/MS07-002", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Excel XP - fixed in 10.0.6823.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6823) { {
 set_kb_item(name:"SMB/Missing/MS07-002", value:TRUE);
 hotfix_security_hole();
 }}
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # Excel 2003 - fixed in 11.0.8117.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8117) { {
 set_kb_item(name:"SMB/Missing/MS07-002", value:TRUE);
 hotfix_security_hole();
 }}
 }
}

