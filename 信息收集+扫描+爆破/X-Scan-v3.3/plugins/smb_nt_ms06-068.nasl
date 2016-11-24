#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(23645);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2006-3445");
 script_bugtraq_id(21034);
 script_xref(name:"OSVDB", value:"30262");
 
 name["english"] = "MS06-068: Vulnerability in Microsoft Agent Could Remote Code Execution (920213)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host through the
agent service." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Microsoft Agent service 
which may allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to set up a rogue web site and 
lure a victim on the remote host into visiting it or have him load a malformed
.ACF file." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-068.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 920213";

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


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( ( hotfix_check_fversion(file:"msagent\Agentsvr.exe", version:"2.0.0.3424") == HCF_OLDER ) ||
      ( hotfix_check_fversion(file:"msagent\Agentsvr.exe", version:"5.2.3790.1242", min_version:"5.2.3790.0") == HCF_OLDER ) )
 {
 set_kb_item(name:"SMB/Missing/MS06-068", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

