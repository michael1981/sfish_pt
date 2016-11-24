#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25484);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2007-2218");
 script_bugtraq_id(24416);
 script_xref(name:"OSVDB", value:"35347");

 name["english"] = "MS07-031: Vulnerability in the Windows Schannel Security Package Could Allow Remote Code Execution (935840)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
browser." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that has a bug in the
SSL/TLS server-key exchange handling routine that may allow an
attacker to execute arbitrary code on the remote host by luring a user
on the remote host into visiting a rogue web site. 

On Windows 2000 and 2003 this vulnerability only results in a crash of
the web browser." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 :

http://www.microsoft.com/technet/security/Bulletin/MS07-031.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 935840";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(xp:3, win2003:3, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:2, file:"Schannel.dll", version:"5.2.3790.4068", dir:"\System32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Schannel.dll", version:"5.2.3790.2924", dir:"\System32") ||
      hotfix_is_vulnerable (os:"5.1", file:"Schannel.dll", version:"5.1.2600.3126", dir:"\System32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Schannel.dll", version:"5.1.2195.7136", dir:"\System32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-031", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
