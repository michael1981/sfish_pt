#
# (C) Tenable Network Security, Inc.
#

# Also supercedes MS02-005, MS02-047, MS02-027, MS02-023, MS02-015, MS01-015


include("compat.inc");

if(description)
{
 script_id(10861);
 script_version("$Revision: 1.86 $");
 script_cve_id("CVE-2002-0057");
 script_bugtraq_id(3699); 
 script_xref(name:"OSVDB", value:"3032");

 script_name(english:"MS02-005: MSIE 5.01 5.5 6.0 Cumulative Patch (890923)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web client." );
 script_set_attribute(attribute:"description", value:
"The Cumulative Patch for IE is not applied on the remote host.

Impact of vulnerability: Run code of attacker's choice." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for the Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-020.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines whether the hotfix 890923 is installed");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(xp:3, win2003:1, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Mshtml.dll", version:"6.0.3790.279", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mshtml.dll", version:"6.0.2800.1498", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.2627", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1498", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:3, file:"Mshtml.dll", version:"5.0.3539.2400", dir:"\system32") || 
      hotfix_is_vulnerable (os:"5.0", sp:4, file:"Mshtml.dll", version:"5.0.3826.2400", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS02-005", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
   hotfix_check_fversion_end();
 
 exit (0);
}
