#
# (C) Tenable Network Security
#
#


include("compat.inc");

if(description)
{
 script_id(29312);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2007-0064");
 script_bugtraq_id(26776);
 script_xref(name:"OSVDB", value:"39122");

 name["english"] = "MS07-068: Vulnerability in Windows Media File Format Could Allow Remote Code Execution (941569 and 944275)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Media File Format." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Windows Media Player/Service.

There is a vulnerability in the remote version of this software which may
allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, one attacker would need to set up a rogue
ASF file and send it to a victim on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and Vista:

http://www.microsoft.com/technet/security/bulletin/ms07-068.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks the version of Media Format";

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

port = kb_smb_transport ();


if ( hotfix_check_sp(xp:3, win2k:6, win2003:3, vista:1) <= 0 ) exit(0);


if (is_accessible_share())
{
  if ( hotfix_is_vulnerable (os:"6.0", file:"wmasf.dll", version:"11.0.6000.6345", min_version:"11.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.2", sp:1, file:"wmsserver.dll", version:"9.1.1.3844", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.2", sp:2, file:"wmsserver.dll", version:"9.1.1.3862", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x86", file:"wmasf.dll", version:"10.0.0.3710", min_version:"10.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.2", sp:2, arch:"x86", file:"wmasf.dll", version:"10.0.0.4000", min_version:"10.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x64", file:"wwmasf.dll", version:"10.0.0.3710", min_version:"10.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.2", sp:2, arch:"x64", file:"wwmasf.dll", version:"10.0.0.4000", min_version:"10.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.2", arch:"x64", file:"wmasf.dll", version:"10.0.0.3811", min_version:"10.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", file:"wmasf.dll", version:"9.0.0.3267", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", file:"wmasf.dll", version:"10.0.0.4060", min_version:"10.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", file:"wmasf.dll", version:"11.0.5721.5238", min_version:"11.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.0", file:"wmasf.dll", version:"7.10.0.3081", min_version:"7.10.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.0", file:"wmasf.dll", version:"9.0.0.3267", min_version:"9.0.0.0", dir:"\system32") )
  {
    hotfix_security_hole(); 
    set_kb_item(name:"SMB/Missing/MS07-068", value:TRUE);
  }

   hotfix_check_fversion_end(); 
}

