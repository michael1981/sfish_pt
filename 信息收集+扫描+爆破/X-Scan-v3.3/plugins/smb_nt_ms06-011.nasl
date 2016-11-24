#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(21077);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2006-0023");
 script_bugtraq_id(16484);
 script_xref(name:"OSVDB", value:"23044");
 script_xref(name:"OSVDB", value:"23045");
 script_xref(name:"OSVDB", value:"23046");
 script_xref(name:"OSVDB", value:"23047");

 name["english"] = "MS06-011: Permissive Windows Services DACLs Could Allow Elevation of Privilege (914798)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Local users may be able to elevate their privileges on the remote
host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains services whose permissions are
set to such a way that low-privileged local users may be able to
change properties associated to each service and therefore manage to
elevate their privileges. 

To exploit this flaw, an attacker would need credentials to log into
the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-011.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 914798";
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


if ( hotfix_check_sp(xp:2, win2003:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"914798") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS06-011", value:TRUE);
 hotfix_security_warning();
 }


