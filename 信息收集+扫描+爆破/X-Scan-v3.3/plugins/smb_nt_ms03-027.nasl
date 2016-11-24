#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11792);
 script_version("$Revision: 1.23 $");

 script_cve_id("CVE-2003-0306");
 script_bugtraq_id(8208);
 script_xref(name:"OSVDB", value:"13409");
 
 name["english"] = "MS03-027: Buffer overrun in Windows Shell (821557)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Explorer." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that has a flaw in its
shell.  An attacker could exploit it by creating a malicious
Desktop.ini file, put it on a shared folder and wait for someone to
browse it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms03-027.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for hotfix Q823980";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Shell32.dll", version:"6.0.2800.1233", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Shell32.dll", version:"6.0.2800.115", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-027", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"839645") > 0 &&
     hotfix_missing(name:"821157") > 0 &&
     hotfix_missing(name:"841356") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS03-027", value:TRUE);
 hotfix_security_hole();
 }

