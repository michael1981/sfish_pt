#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34476);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2008-4250");
 script_bugtraq_id(31874);
 script_xref(name:"OSVDB", value:"49243");

 name["english"] = "MS08-067: Microsoft Windows Server Service Crafted RPC Request Handling Unspecified Remote Code Execution (958644)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the 
'server' service." );
 script_set_attribute(attribute:"description", value:
"The remote host is vulnerable to a buffer overrun in the 'Server' service
which may allow an attacker to execute arbitrary code on the remote host
with the 'System' privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003, Vista and 2008 :

http://www.microsoft.com/technet/security/bulletin/ms08-067.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 958644";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:4, win2003:3, win2k:6, vista:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( 
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Netapi32.dll", version:"6.0.6001.22288", min_version:"6.0.6001.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Netapi32.dll", version:"6.0.6001.18157", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Netapi32.dll", version:"6.0.6000.20937", min_version:"6.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Netapi32.dll", version:"6.0.6000.16764", dir:"\system32") ||

      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Netapi32.dll", version:"5.2.3790.4392", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Netapi32.dll", version:"5.2.3790.3229", dir:"\system32") ||

      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Netapi32.dll", version:"5.1.2600.5694", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Netapi32.dll", version:"5.1.2600.3462", dir:"\system32") ||

      hotfix_is_vulnerable (os:"5.0", file:"Netapi32.dll", version:"5.0.2195.7203", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS08-067", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
