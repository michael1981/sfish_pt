#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20885);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2002-0055");
 script_bugtraq_id(4204);
 script_xref(name:"OSVDB", value:"732");

 script_name(english:"MS02-012: Malformed Data Transfer Request can Cause Windows SMTP Service to Fail (313450)");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the mail service." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a flaw in its SMTP service that could allow
an attacker to crash it. 

Vulnerable services are SMTP service (Windows XP/Windows 2000) and
Exchange 2000 (Windows 2000)." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-012.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q313450");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(win2k:5, xp:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Smtpsvc.dll", version:"6.0.2600.28", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Smtpsvc.dll", version:"5.0.2195.4905", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS02-012", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
