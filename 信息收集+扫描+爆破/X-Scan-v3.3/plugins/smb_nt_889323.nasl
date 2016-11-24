#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(17607);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2005-0904");
 script_bugtraq_id(12889);
 script_xref(name:"OSVDB", value:"15011");
 name["english"] = "Non administrators can shut down Windows XP SP1 thru TSShutdn.exe (889323)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to shutdown the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Microsoft Windows XP SP1 lacks the security update 
889323.

A non-administrative user can remotely shut down the remote host by using
the TSShutdn.exe command." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP :

http://support.microsoft.com/kb/889323/" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks the remote registry for KB 889323";

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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


# Only XP SP1 affected
if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Termsrv.dll", version:"5.1.2600.1646", dir:"\system32") )
   security_warning(get_kb_item("SMB/transport"));
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"889323") > 0 )
	security_warning(get_kb_item("SMB/transport"));
