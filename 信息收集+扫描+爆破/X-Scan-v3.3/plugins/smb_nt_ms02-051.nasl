#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11146);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2002-0863", "CVE-2002-0864");
 script_bugtraq_id(5711, 5712);
 script_xref(name:"OSVDB", value:"866");
 script_xref(name:"OSVDB", value:"13421");

 script_name(english:"MS02-051: Cryptographic Flaw in RDP Protocol can Lead to Information Disclosure (324380)");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote desktop service." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Remote Desktop protocol /
service that may allow an attacker to crash the remote service and
cause the system to stop responding.  Another vulnerability may allow
an attacker to disclose information." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-051.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q324380, Flaws in Microsoft RDP");
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

if ( hotfix_check_sp(xp:1, win2k:4) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Rdpwd.sys", version:"5.1.2600.48", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Rdpwd.sys", version:"5.0.2195.5880", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS02-051", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q324380") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS02-051", value:TRUE);
 hotfix_security_hole();
 }

