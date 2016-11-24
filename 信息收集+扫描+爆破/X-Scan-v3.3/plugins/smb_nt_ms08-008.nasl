#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(31042);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2007-0065");
 script_bugtraq_id(27661);

 name["english"] = "MS08-008: Vulnerability in OLE Automation Could Allow Remote Code Execution (947890)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web or
email client." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Windows which has a
vulnerability in the OLE Automation component which could be abused by an 
attacker to execute arbitrary code on the remote host.

An attacker may be able to execute arbitrary code on the remote host
by constructing a malicious script and enticing a victim to visit a
web site or view a specially-crafted email message." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and Vista :

http://www.microsoft.com/technet/security/Bulletin/MS08-008.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 947890";

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

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

if ( hotfix_check_sp(xp:3, win2003:3, win2k:6, vista:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Oleaut32.dll", version:"6.0.6000.20732", min_version:"6.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Oleaut32.dll", version:"6.0.6000.16607", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Oleaut32.dll", version:"5.2.3790.4202", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Oleaut32.dll", version:"5.2.3790.3057", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Oleaut32.dll", version:"5.1.2600.3266", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Oleaut32.dll", version:"2.40.4532.0", dir:"\system32") )
   	 {
 set_kb_item(name:"SMB/Missing/MS08-008", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
