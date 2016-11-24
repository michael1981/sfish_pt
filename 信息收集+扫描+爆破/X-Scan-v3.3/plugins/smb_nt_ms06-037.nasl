#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22031);
 script_version("$Revision: 1.11 $");

 script_cve_id(
  "CVE-2006-1301",
  "CVE-2006-1302",
  "CVE-2006-1304",
  "CVE-2006-1306",
  "CVE-2006-1308",
  "CVE-2006-1309",
  "CVE-2006-2388",
  "CVE-2006-3059"
 );
 script_bugtraq_id(18422, 18853, 18938, 18910, 18890, 18888, 18886, 18885);
 script_xref(name:"OSVDB", value:"26527");
 script_xref(name:"OSVDB", value:"28532");
 script_xref(name:"OSVDB", value:"28533");
 script_xref(name:"OSVDB", value:"28534");
 script_xref(name:"OSVDB", value:"28535");
 script_xref(name:"OSVDB", value:"28536");
 script_xref(name:"OSVDB", value:"28537");
 script_xref(name:"OSVDB", value:"28538");

 name["english"] = "MS06-037: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (917285)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Excel." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Excel that may allow
arbitrary code to be run. 

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have him open it with Microsoft Excel." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-037.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the version of Excel.exe";
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
# Excel
#
v = get_kb_item("SMB/Office/Excel/Version");
if ( v ) 
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Excel 2000 - fixed in 9.00.00.8946
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8946 ) { {
 set_kb_item(name:"SMB/Missing/MS06-037", value:TRUE);
 hotfix_security_warning();
 }}
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Excel XP - fixed in 10.0.6809.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6809) { {
 set_kb_item(name:"SMB/Missing/MS06-037", value:TRUE);
 hotfix_security_warning();
 }}
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # Excel 2003 - fixed in 11.0.8033.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8033) { {
 set_kb_item(name:"SMB/Missing/MS06-037", value:TRUE);
 hotfix_security_warning();
 }}
 }
}

