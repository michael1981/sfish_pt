#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(11802);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2003-0525");
 script_bugtraq_id(8259);
 script_xref(name:"OSVDB", value:"12654");
 
 name["english"] = "MS03-029: Flaw in Windows Function may allow DoS (823803)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows NT 4.0 that has a flaw
in one of its functions that may allow a user to cause a denial of
service on this host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT :

http://www.microsoft.com/technet/security/bulletin/ms03-029.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for hotfix 823803";
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

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"4.0", file:"Kernel32.dll", version:"4.0.1381.7224", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Kernel32.dll", version:"4.0.1381.33549", min_version:"4.0.1381.33000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-029", value:TRUE);
 hotfix_security_note();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q823803") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS03-029", value:TRUE);
 hotfix_security_note();
 }
