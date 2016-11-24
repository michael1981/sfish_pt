#
# (C) Tenable Network Security
#
#


include("compat.inc");

if(description)
{
 script_id(23838);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2006-4702", "CVE-2006-6134");
 script_bugtraq_id(21247, 21505);
 script_xref(name:"OSVDB", value:"30818");
 script_xref(name:"OSVDB", value:"30819");
 
 name["english"] = "MS06-078: Vulnerability in Windows Media Format Could Allow Remote Code Execution (923689/925398)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Media Format Series." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Windows Media Player/Series.

There is a vulnerability in the remote version of this software which may
allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, one attacker would need to set up a rogue
ASF/ASX file and send it to a victim on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-078.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks the version of Media Format";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
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

port = kb_smb_transport ();


if ( hotfix_check_sp(xp:3, win2k:6, win2003:3) <= 0 ) exit(0);


if (is_accessible_share())
{
  if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Wmvcore.dll", version:"9.0.0.3265", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.2", arch:"x86", file:"Wmvcore.dll", version:"10.0.0.3708", min_version:"10.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.2", file:"Dxmasf.dll", version:"6.4.9.1133", min_version:"6.4.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", file:"Wmvcore.dll", version:"9.0.0.3265", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", file:"Wmvcore.dll", version:"10.0.0.3702", min_version:"10.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", file:"Dxmasf.dll", version:"6.4.9.1133", min_version:"6.4.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.0", file:"Wmvcore.dll", version:"7.10.0.3079", min_version:"7.10.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.0", file:"Wmvcore.dll", version:"9.0.0.3265", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.0", file:"Dxmasf.dll", version:"6.4.9.1133", min_version:"6.4.0.0", dir:"\system32") )
  {
    hotfix_security_hole();
    set_kb_item(name:"SMB/Missing/MS06-078", value:TRUE);
  }

   hotfix_check_fversion_end(); 
}
