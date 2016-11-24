#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18482);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2005-1208");
 script_bugtraq_id(13953);
 script_xref(name:"IAVA", value:"2005-A-0017");
 script_xref(name:"OSVDB", value:"17305");

 name["english"] = "MS05-026: Vulnerability in HTML Help Could Allow Remote Code Execution (896358)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web client." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the HTML Help ActiveX control which
is vulnerable to a security flaw which may allow an attacker to execute
arbitrary code on the remote host by constructing a malicious web page
and entice a victim to visit this web page." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-026.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );



script_end_attributes();

 
 summary["english"] = "Determines the presence of update 896358";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Hhctrl.ocx", version:"5.2.3790.315", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Hhctrl.ocx", version:"5.2.3790.2427", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Hhctrl.ocx", version:"5.2.3790.315", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Hhctrl.ocx", version:"5.2.3790.2453", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Hhctrl.ocx", version:"5.2.3790.309", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-026", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

