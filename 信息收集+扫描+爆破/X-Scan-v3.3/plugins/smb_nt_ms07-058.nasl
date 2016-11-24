#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(26964);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2007-2228");
 script_bugtraq_id(25974);
 script_xref(name:"OSVDB", value:"37628");
 script_xref(name:"OSVDB", value:"37629");
 
 name["english"] = "MS07-058: Vulnerability in RPC Could Allow Denial of Service (933729)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of the RPC library
protocol that is vulnerable to a denial of service attack in the NTLM
authentication field. 

An attacker may exploit this flaw to crash the remote RPC server (and
the remote system)." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista :

http://www.microsoft.com/technet/security/bulletin/ms07-058.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 933729";

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


if ( hotfix_check_sp(xp:3, win2003:3, win2k:6, vista:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Rpcrt4.dll", version:"6.0.6000.20641", min_version:"6.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Rpcrt4.dll", version:"6.0.6000.16525", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Rpcrt4.dll", version:"5.2.3790.2971", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Rpcrt4.dll", version:"5.2.3790.4115", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Rpcrt4.dll", version:"5.1.2600.3173", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Rpcrt4.dll", version:"5.0.2195.7090", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-058", value:TRUE);
 hotfix_security_hole();
 }
 hotfix_check_fversion_end(); 
}
