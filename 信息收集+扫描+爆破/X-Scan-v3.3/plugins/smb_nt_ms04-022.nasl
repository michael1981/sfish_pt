#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(13640);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-0212");
 script_bugtraq_id(10708);
 script_xref(name:"IAVA", value:"2004-A-0013");
 script_xref(name:"OSVDB", value:"7798");

 name["english"] = "MS04-022: Task Scheduler Vulnerability (841873)";

 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows which contains a flaw in
the task scheduler which may lead to arbitrary execution of commands 
on the remote host.

To exploit this vulnerability, an attacker would need to lure a user on
the remote host to take certain steps to execute a .job file, or to visit
a rogue web site, then he may be able to execute arbitrary commands on the 
remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms04-022.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks for ms04-022 over the registry";

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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mstask.dll", version:"5.1.2600.1564", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Mstask.dll", version:"5.1.2600.155", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mstask.dll", version:"4.71.2195.6920", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Mstask.dll", version:"4.71.1979.1", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-022", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"KB841873") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS04-022", value:TRUE);
 hotfix_security_hole();
 }

