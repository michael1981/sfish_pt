#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22029);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2006-1314", "CVE-2006-1315");
 script_bugtraq_id(18891, 18863);
 script_xref(name:"OSVDB", value:"27154");
 script_xref(name:"OSVDB", value:"27155");

 name["english"] = "MS06-035: Vulnerability in Server Service Could Allow Remote Code Execution (917159)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the 
'server' service." );
 script_set_attribute(attribute:"description", value:
"The remote host is vulnerable to heap overflow in the 'Server' service that
may allow an attacker to execute arbitrary code on the remote host with
the 'System' privileges.

In addition to this, the remote host is also vulnerable to an
information disclosure attack in SMB that may allow an attacker to
obtain portions of the memory of the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-035.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 917159";

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


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Srv.sys", version:"5.2.3790.526", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Srv.sys", version:"5.2.3790.2691", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Srv.sys", version:"5.1.2600.1832", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Srv.sys", version:"5.1.2600.2893", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Srv.sys", version:"5.0.2195.7087", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS06-035", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

