#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11888);
 script_version("$Revision: 1.24 $");

 script_cve_id("CVE-2003-0717");
 script_bugtraq_id(8826);
 script_xref(name:"IAVA", value:"2003-b-0007");
 script_xref(name:"IAVA", value:"2003-a-0017");
 script_xref(name:"IAVA", value:"2003-B-0017");
 script_xref(name:"OSVDB", value:"10936");
 
 script_name(english:"MS03-043: Buffer Overrun in Messenger Service (828035)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a Heap Overflow in the Messenger
service which may allow an attacker to execute arbitrary code on the
remote host with the SYSTEM privileges.

A series of worms (Gaobot, Agobot, ...) are known to exploit this
vulnerability in the wild." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms03-043.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for hotfix Q828035");
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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Msgsvc.dll", version:"5.2.3790.90", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Msgsvc.dll", version:"5.1.2600.1309", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Msgsvc.dll", version:"5.1.2600.121", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Msgsvc.dll", version:"5.0.2195.6861", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Msgsvc.dll", version:"4.0.1381.7236", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Msgsvc.dll", version:"4.0.1381.33553", min_version:"4.0.1381.33000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-043", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"KB828035") > 0  )
	 {
 set_kb_item(name:"SMB/Missing/MS03-043", value:TRUE);
 hotfix_security_hole();
 }

