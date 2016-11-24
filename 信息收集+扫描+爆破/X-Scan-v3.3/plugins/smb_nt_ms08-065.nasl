#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(34410);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-3479");
 script_bugtraq_id(31637);
 script_xref(name:"OSVDB", value:"49060");

 name["english"] = "MS08-065: Microsoft Windows Message Queuing Service RPC Request Handling Remote Code Execution (951071)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows is affected by a vulnerability in 
Microsoft Message Queuing Service (MSMQ).

An attacker may exploit this flaw to execute arbitrary code on the remote
host with the SYSTEM privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms08-065.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines if hotfix 951071 has been installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_hotfixes.nasl" );
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");

if ( hotfix_check_sp(win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Mqqm.dll", version:"5.0.0.807", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS08-065", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
