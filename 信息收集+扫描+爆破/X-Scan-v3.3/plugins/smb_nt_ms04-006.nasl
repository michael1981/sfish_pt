#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12051);
 script_version("$Revision: 1.23 $");

 script_cve_id("CVE-2003-0825");
 script_bugtraq_id(9624);
 script_xref(name:"OSVDB", value:"3903");

 script_name(english:"MS04-006: WINS Server Remote Overflow (830352)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote Windows Internet Naming Service (WINS) is vulnerable to a 
flaw which could allow an attacker to execute arbitrary code on this host.

To exploit this flaw, an attacker would need to send a specially crafted
packet with improperly advertised lengths." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-006.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks the remote registry for MS04-006");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_nt_server() <= 0 ) exit(0);
if ( hotfix_check_wins_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7, win2k:5, win2003:1) <= 0 ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Wins.exe", version:"5.2.3790.99", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Wins.exe", version:"5.0.2195.6870", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Wins.exe", version:"4.0.1381.7255", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Wins.exe", version:"4.0.1381.33554", min_version:"4.0.1381.33000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-006", value:TRUE);
 hotfix_security_hole();
 }

 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"830352") > 0 &&
          hotfix_missing(name:"870763") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS04-006", value:TRUE);
 hotfix_security_hole();
 }
