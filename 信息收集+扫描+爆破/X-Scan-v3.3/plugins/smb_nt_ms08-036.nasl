#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33137);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-1440", "CVE-2008-1441");
 script_bugtraq_id(29508, 29509);
 script_xref(name:"OSVDB", value:"46067");
 script_xref(name:"OSVDB", value:"46068");

 name["english"] = "MS08-036: Vulnerabilities in Pragmatic General Multicast (PGM) Could Allow Denial of Service (950762)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"An unauthenticated attacker can crash the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows is affected by a vulnerability in the
Pragmatic General Multicast protocol installed with the MSMQ service. 

An attacker may exploit this flaw to crash the remote host remotely." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista
and 2008 :

http://www.microsoft.com/technet/security/bulletin/ms08-036.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines if hotfix 950762 has been installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_hotfixes.nasl" );
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");

if ( hotfix_check_sp(xp:4,win2003:3,vista:2,win2008:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( 
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Rmcast.sys", version:"6.0.6000.20832", min_version:"6.0.6000.20000", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Rmcast.sys", version:"6.0.6000.16687", dir:"\system32\drivers") ||
      hotfix_is_vulnerable(os:"6.1", sp:1, file:"Rmcast.sys", version:"6.0.6001.22176", min_version:"6.0.6001.22000", dir:"\system32\drivers") ||
      hotfix_is_vulnerable(os:"6.1", sp:1, file:"Rmcast.sys", version:"6.0.6001.18069", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Rmcast.sys", version:"5.2.3790.3136", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Rmcast.sys", version:"5.2.3790.4290", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Rmcast.sys", version:"5.1.2600.3369", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Rmcast.sys", version:"5.1.2600.5598", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS08-036", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
