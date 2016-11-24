#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(29307);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2007-5351");
 script_bugtraq_id(26777);
 script_xref(name:"OSVDB", value:"39125");

 name["english"] = "MS07-063: Vulnerability in SMBv2 Could Allow Remote Code Execution (942624)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of SMBv2 (Server
Message Block) protocol that has several vulnerabilities. 

An attacker may exploit these flaws to elevate his privileges and gain
control of the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista :

http://www.microsoft.com/technet/security/bulletin/ms07-063.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 942624";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(vista:1) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mrxsmb.sys", version:"6.0.6000.16586", dir:"\system32\drivers") ||
     hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mrxsmb.sys", version:"6.0.6000.20709", min_version:"6.0.6000.20000", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS07-063", value:TRUE);
 hotfix_security_hole();
 }
      hotfix_check_fversion_end(); 
}
