#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(11787);
 script_version("$Revision: 1.31 $");

 script_cve_id("CVE-2003-0345");
 script_bugtraq_id(8152);
 script_xref(name:"OSVDB", value:"11801");
 
 name["english"] = "MS03-024: SMB Request Handler Buffer Overflow (817606)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is vulnerable to a flaw in its SMB stack which may allow
an authenticated attacker to corrupt the memory of this host. This
may result in execution of arbitrary code on this host, or an attacker
may disable this host remotely." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP :

http://www.microsoft.com/technet/security/bulletin/ms03-024.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks for hotfix Q817606";

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

if ( hotfix_check_sp(xp:3, win2k:5) > 0 && hotfix_missing(name:"896422") == 0 ) exit(0);

if ( hotfix_check_sp(nt:7, win2k:5, xp:3) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Srv.sys", version:"5.1.2600.1193", dir:"\system32\Drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Srv.sys", version:"5.1.2600.112", dir:"\system32\Drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Srv.sys", version:"5.0.2195.6699", dir:"\system32\Drivers") ||
      hotfix_is_vulnerable (os:"4.0", file:"Srv.sys", version:"4.0.1381.7214", dir:"\system32\Drivers") ||
      hotfix_is_vulnerable (os:"4.0", file:"Srv.sys", version:"4.0.1381.33547", min_version:"4.0.1381.33000", dir:"\system32\Drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS03-024", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"817606") > 0 && 
	  hotfix_missing(name:"896422") > 0 &&
	  hotfix_missing(name:"917159") > 0 &&
          hotfix_missing(name:"923414") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS03-024", value:TRUE);
 hotfix_security_hole();
 }

