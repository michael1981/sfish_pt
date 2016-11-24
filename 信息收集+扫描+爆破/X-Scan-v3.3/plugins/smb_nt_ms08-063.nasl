#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34408);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-4038");
 script_bugtraq_id(31647);
 script_xref(name:"OSVDB", value:"49057");

 name["english"] = "MS08-063: Microsoft Windows SMB File Name Handling Remote Underflow (957095)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote host due to a flaw in the 'server'
service." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a memory corruption vulnerability in the
'Server' service that may allow an attacker to perform a denial of
service against the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008 :

http://www.microsoft.com/technet/security/bulletin/ms08-063.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 957095";

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


if ( hotfix_check_sp(xp:4, win2003:3, win2k:6, vista:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( 
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Srv.sys", version:"6.0.6000.16738", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Srv.sys", version:"6.0.6000.20904", min_version:"6.0.6000.20000", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Srv.sys", version:"6.0.6001.18130", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Srv.sys", version:"6.0.6001.22252", min_version:"6.0.6001.20000", dir:"\system32\drivers") ||

      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Srv.sys", version:"5.2.3790.4363", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Srv.sys", version:"5.2.3790.3200", dir:"\system32\drivers") ||

      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Srv.sys", version:"5.1.2600.5671", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Srv.sys", version:"5.1.2600.3436", dir:"\system32\drivers") ||

      hotfix_is_vulnerable (os:"5.0", file:"Srv.sys", version:"5.0.2195.7177", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS08-063", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

