#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25688);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2007-1754");
 script_bugtraq_id(22702);
 script_xref(name:"OSVDB", value:"35953");

 name["english"] = "MS07-037: Vulnerability in Microsoft Publisher Could Allow Remote Code Execution (936548)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Publisher." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Publisher that may
allow arbitrary code to be run. 

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Publisher 2007 :

http://www.microsoft.com/technet/security/bulletin/ms07-037.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the version of MSPUB.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl");
 script_require_keys("SMB/Office/Publisher/Version");
 exit(0);
}

include("smb_hotfixes_fcheck.inc");

port = get_kb_item("SMB/transport");

v = get_kb_item("SMB/Office/Publisher/Version");
if ( v ) 
{
 if(ereg(pattern:"^12\..*", string:v))
 {
  # Publisher XP - fixed in 10.0.6023.5000
   middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
   low =  ereg_replace(pattern:"^12\.0\.[0-9]*\.([0-9]*)$", string:v, replace:"\1");
   if(middle != v && int(middle) < 6023 || ( int(middle) == 6023 && int(low) < 5000)) {
 set_kb_item(name:"SMB/Missing/MS07-037", value:TRUE);
 hotfix_security_hole();
 }
 }
}
