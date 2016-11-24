#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15459);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2004-0575");
 script_bugtraq_id(11382);
 script_xref(name:"OSVDB", value:"10695");

 name["english"] = "MS04-034: Vulnerability in zipped folders may allow code execution (873376)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Explorer." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows is vulnerable to a bug in the way it
handles compressed (zipped) folders, that may in turn be exploited by
an attacker to execute arbitrary code on the remote host. 

To exploit this flaw, an attacker would need to send a specially
crafted .zip file to a victim on the remote host and wait for him to
browse the file using the Windows Explorer." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-034.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines if hotfix 873376 has been installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Zipfldr.dll", version:"6.0.3790.198", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Zipfldr.dll", version:"6.0.2800.1584", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Zipfldr.dll", version:"6.0.2750.167", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-034", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"873376") > 0  )
	 {
 set_kb_item(name:"SMB/Missing/MS04-034", value:TRUE);
 hotfix_security_hole();
 }

