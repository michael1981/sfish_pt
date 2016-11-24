#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33132);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2008-1453");
 script_bugtraq_id(29522);
 script_xref(name:"OSVDB", value:"46061");

 name["english"] = "MS08-030: Vulnerability in Bluetooth Stack Could Allow Remote Code Execution (951376)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Bluetooth." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Windows Bluetooth stack
which is vulnerable to a security flaw in the service description
request handle which may allow a remote attacker to execute code with
SYSTEM privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and Vista :

http://www.microsoft.com/technet/security/bulletin/ms08-030.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks MS patch 951376";

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


if ( hotfix_check_sp(xp:4, vista:2) <= 0 ) exit(0);

if (is_accessible_share())
{
      if ( hotfix_is_vulnerable (os:"6.0", sp:1, file:"Bthport.sys", version:"6.0.6001.22168", min_version:"6.0.6001.20000", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Bthport.sys", version:"6.0.6001.18064", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Bthport.sys", version:"6.0.6000.20824", min_version:"6.0.6000.20000", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Bthport.sys", version:"6.0.6000.16682", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Bthport.sys", version:"5.1.2600.5620", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Bthport.sys", version:"5.1.2600.3389", dir:"\system32\drivers") )
   	 {
 set_kb_item(name:"SMB/Missing/MS08-030", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
