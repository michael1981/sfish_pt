#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34122);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-2253");
 script_bugtraq_id(30550);
 script_xref(name:"OSVDB", value:"47963");
 
 name["english"] = "MS08-054: Vulnerability in Windows Media Player Could Allow Remote Code Execution (954154)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Media
Player." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Windows Media Player 11. 

There is a vulnerability in the remote version of this software which
may allow an attacker to execute arbitrary code on the remote host. 

To exploit this flaw, one attacker would need to set up a rogue audio
file and send it to a victim on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Media Player 11 :

http://www.microsoft.com/technet/security/bulletin/ms08-054.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks the version of Media Player";

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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(xp:4, vista:2, win2008:2) <= 0 ) exit(0);

version = get_kb_item("SMB/WindowsMediaPlayer");
if(!version)exit(0);


if (is_accessible_share())
{
  if ( hotfix_is_vulnerable (os:"6.0", file:"Wmpeffects.dll", version:"11.0.6000.6347", min_version:"11.0.6000.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"6.0", file:"Wmpeffects.dll", version:"11.0.6000.6506", min_version:"11.0.6000.6500", dir:"\system32") ||
       hotfix_is_vulnerable (os:"6.0", file:"Wmpeffects.dll", version:"11.0.6001.7002", min_version:"11.0.6001.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"6.0", file:"Wmpeffects.dll", version:"11.0.6001.7106", min_version:"11.0.6001.7100", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", file:"Wmpeffects.dll", version:"11.0.5721.5252", min_version:"11.0.0.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS08-054", value:TRUE);
 hotfix_security_hole();
 }

   hotfix_check_fversion_end(); 
}
