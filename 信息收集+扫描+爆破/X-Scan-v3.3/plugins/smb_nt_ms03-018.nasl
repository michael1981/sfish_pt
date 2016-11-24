#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11683);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2003-0223", "CVE-2003-0224", "CVE-2003-0225", "CVE-2003-0226");
 script_bugtraq_id(7731, 7733, 7734, 7735);
 script_xref(name:"OSVDB", value:"4655");
 script_xref(name:"OSVDB", value:"4863");
 script_xref(name:"OSVDB", value:"7737");
 script_xref(name:"OSVDB", value:"13385");

 script_name(english:"MS03-018: Cumulative Patch for Internet Information Services (11114)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote web server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of IIS that contains various
flaws that may allow remote attackers to disable this service remotely
and local attackers (or remote attackers with the ability to upload
arbitrary files on this server) to gain SYSTEM level access on this
host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for IIS 4.0, 5.0 and 5.1 :

http://www.microsoft.com/technet/security/bulletin/ms03-018.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines if HF Q811114 has been installed");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_iis_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", file:"W3svc.dll", version:"5.1.2600.1166", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"5.0", file:"W3svc.dll", version:"5.0.2195.6672", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"4.0", file:"W3svc.dll", version:"4.2.785.1", dir:"\system32\inetsrv") )
 {
 set_kb_item(name:"SMB/Missing/MS03-018", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q811114") > 0  )
	 {
 set_kb_item(name:"SMB/Missing/MS03-018", value:TRUE);
 hotfix_security_hole();
 }

