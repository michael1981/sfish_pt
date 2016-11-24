#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(18215);
 script_version("$Revision: 1.14 $");

 script_bugtraq_id(13248);
 script_cve_id("CVE-2005-1191");
 script_xref(name:"IAVA", value:"2005-t-0016");
 script_xref(name:"OSVDB", value:"15707");

 name["english"] = "MS05-024: Vulnerability in Web View Could Allow Code Execution (894320)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Explorer." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Windows which contains a 
security flaw in the Web View of the Windows Explorer which may allow an 
attacker to execute arbitrary code on the remote host.

To succeed, the attacker would have to send a rogue file to a user of the 
remote computer and have it preview it using the Web View with the Windows 
Explorer." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms05-024.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );



script_end_attributes();

 
 summary["english"] = "Determines the presence of KB894320";

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

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");

if ( hotfix_check_sp(win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Webvw.dll", version:"5.0.3900.7036", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-024", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"894320") > 0 &&
          hotfix_missing(name:"900725") > 0  )
 {
 set_kb_item(name:"SMB/Missing/MS05-024", value:TRUE);
 hotfix_security_hole();
 }
