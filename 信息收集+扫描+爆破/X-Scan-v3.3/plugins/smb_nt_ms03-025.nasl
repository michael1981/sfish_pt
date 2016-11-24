#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11789);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2003-0350");
 script_bugtraq_id(8154);
 script_xref(name:"OSVDB", value:"13410");
 
 name["english"] = "MS03-025: Flaw in message handling through utility mgr (822679)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges." );
 script_set_attribute(attribute:"description", value:
"The remote host runs a version of Windows that has a flaw in the way
the utility manager handles Windows messages.  As a result, it is
possible for a local user to gain additional privileges on this host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms03-025.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for hotfix Q822679";
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

if ( hotfix_check_sp(win2k:4) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Umandlg.dll", version:"1.0.0.3", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-025", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"822679") > 0 && hotfix_missing(name:"842526") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS03-025", value:TRUE);
 hotfix_security_hole();
 }
