#
# (C) Tenable Network Security, Inc.
#

# MS03-033 supercedes MS02-040
#
# Note: The fix for this issue will be included in MDAC 2.5 Service Pack 5 and in MDAC 2.7 Service Pack 2. 
# The script should be update when the service pack is released.
#
# MS03-033 Prerequisites:
# You must be running one of the following versions of MDAC: 
# MDAC 2.5 Service Pack 2
# MDAC 2.5 Service Pack 3 
# MDAC 2.6 Service Pack 2
# MDAC 2.7 RTM
# MDAC 2.7 Service Pack 1
# Other versions of MDAC are not affected by this vulnerability.  
#
# MS02-040 Fixed in :
#	- MDAC 2.5 SP3
#	- MDAC 2.6 SP3
#	- MDAC 2.7 SP1
#


include("compat.inc");

if(description)
{
 script_id(11301);
 script_version("$Revision: 1.32 $");

 script_cve_id("CVE-2002-0695", "CVE-2003-0353");
 script_bugtraq_id(5372, 8455);
 script_xref(name:"IAVA", value:"2002-A-0010");
 script_xref(name:"OSVDB", value:"5135");
 script_xref(name:"OSVDB", value:"10129");
 
 script_name(english:"MS02-040 / MS03-033: Unchecked buffer in MDAC Function (326573 / 823718)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through MDAC server." );
 script_set_attribute(attribute:"description", value:
"The remote Microsoft Data Access Component (MDAC) server is vulnerable
to a flaw which could allow an attacker to execute arbitrary code on
this host, provided he can load and execute a database query on this
server." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for MDAC 2.6, 2.7 and 2.8 :

http://www.microsoft.com/technet/security/bulletin/ms02-040.mspx
http://www.microsoft.com/technet/security/bulletin/ms03-033.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks the version of MDAC");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl", "smb_nt_ms04-003.nasl");
 script_require_keys("SMB/Registry/Enumerated", "SMB/MDAC_odbcbcp");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

port = kb_smb_transport();

version = get_kb_item ("SMB/MDAC_odbcpcp");
if (!version)
  exit (0);

if ( hotfix_check_sp(nt:7, xp:2, win2k:5) <= 0 ) exit(0);

v = split (version, sep:".", keep:FALSE);

if ( v[0] == 3 )
	{
	 if ( (v[0] == 3 && v[1] < 70) || 
	      (v[0] == 3 && v[1] == 70 && v[2] < 11) ||
	      (v[0] == 3 && v[1] == 70 && v[2] == 11 && v[3] < 40 ) ) { {
 set_kb_item(name:"SMB/Missing/MS03-033", value:TRUE);
 hotfix_security_hole();
 }}
	}
else if ( v[0] == 2000 )
	{
	 if ( ( v[0] == 2000 && v[1] == 80 && v[2] < 746) ||
	      ( v[0] == 2000 && v[1] == 80 && v[2] == 746 && v[3] < 0 ) ) { {
 set_kb_item(name:"SMB/Missing/MS03-033", value:TRUE);
 hotfix_security_hole();
 }}

	 if ( ( v[0] == 2000 && v[1] == 81 && v[2] < 9001) ||
	      ( v[0] == 2000 && v[1] == 81 && v[2] == 9001 && v[3] < 40 ) ) { {
 set_kb_item(name:"SMB/Missing/MS03-033", value:TRUE);
 hotfix_security_hole();
 }}

	 if ( ( v[0] == 2000 && v[1] == 81 && v[2] == 9040) ||
	      ( v[0] == 2000 && v[1] == 81 && v[2] == 9041 && v[3] < 40 ) ) { {
 set_kb_item(name:"SMB/Missing/MS03-033", value:TRUE);
 hotfix_security_hole();
 }}
	}
