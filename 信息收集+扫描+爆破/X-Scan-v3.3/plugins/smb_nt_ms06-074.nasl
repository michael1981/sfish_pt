#
# (C) Tenable Network Security
#
#


include("compat.inc");

if(description)
{
 script_id(23837);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(21537);
 script_xref(name:"OSVDB", value:"30811");
 script_cve_id("CVE-2006-5583");
 name["english"] = "MS06-074: Vulnerability in SNMP Could Allow Remote Code Execution (926247)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a flaw in its SNMP service which could allow remote
code execution." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-074.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks for MS Hotfix 926247";

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

value = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/SNMP/DisplayName");
if (!value)
  exit(0);


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"snmp.exe", version:"5.2.3790.615", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"snmp.exe", version:"5.2.3790.2837", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"snmp.exe", version:"5.1.2600.3038", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"snmp.exe", version:"5.0.2195.7112", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-074", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

