#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20909);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2006-0008");
 script_bugtraq_id(16643);
 script_xref(name:"OSVDB", value:"23136");

 name["english"] = "MS06-009: Vulnerability in Korean Input Method Could Allow Elevation of Privilege (901190)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user may elevate his privileges." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Korean input
method that may allow a local attacker to execute arbitrary code on
the remote host. 

To exploit this flaw, an attacker would need credentials to log into
the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003 and
Office 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-009.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 901190";
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


#
# XP SP1, SP2, Windows Server 2003 SP0, SP1
#
if ( hotfix_check_sp(xp:3, win2003:2) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Imekr61.ime", version:"6.1.3790.1", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Imekr61.ime", version:"6.2.2551.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1",       file:"Imekr61.ime", version:"6.1.2600.3", dir:"\system32")  )
     
 {
 set_kb_item(name:"SMB/Missing/MS06-009", value:TRUE);
 hotfix_security_hole();
 }
 
  hotfix_check_fversion_end(); 
  exit (0);
 }
