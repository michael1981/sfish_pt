#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11147);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2002-0693", "CVE-2002-0694");
 script_bugtraq_id(4387, 5872, 5874);
 script_xref(name:"OSVDB", value:"867");
 script_xref(name:"OSVDB", value:"2992");

 script_name(english:"MS02-055: Unchecked Buffer in Windows Help Facility Could Enable Code Execution (323255)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the HTML Helpfacility ActiveX
control module that may allow an attacker to execute arbitrary code on
the remote host by constructing a malicious web page and enticing a
victim to visit it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-055.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q323255, Unchecked Buffer in Windows Help facility");
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

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", file:"Hhctrl.ocx", version:"5.2.3669.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Hhctrl.ocx", version:"5.2.3669.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Hhctrl.ocx", version:"5.2.3669.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS02-055", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q323255") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS02-055", value:TRUE);
 hotfix_security_hole();
 }
