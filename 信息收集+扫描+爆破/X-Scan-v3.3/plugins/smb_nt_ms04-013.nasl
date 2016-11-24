#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12208);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2004-0380");
 script_bugtraq_id(9105, 9107, 9658);
 script_xref(name:"IAVA", value:"2004-A-0009");
 script_xref(name:"OSVDB", value:"3143");
 script_xref(name:"OSVDB", value:"3144");
 script_xref(name:"OSVDB", value:"3307");
 script_xref(name:"OSVDB", value:"5242");
 
 name["english"] = "MS04-013: Cumulative Update for Outlook Express (837009)";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host has a version of Outlook express that has a bug in its
MHTML URL processor that may allow an attacker to execute arbitrary
code on this host. 

To exploit this flaw, an attacker would need to send a malformed email
to a user of this host using Outlook, or would need to lure him into
visiting a rogue website." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-013.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for ms04-013";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl", "smb_nt_ms04-018.nasl", "smb_nt_ms05-030.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

port = get_kb_item("SMB/transport");
if(!port) port = 139;

if ( hotfix_check_sp(win2k:5,xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"823353") <= 0 ) exit(0);
if ( get_kb_item("SMB/897715") ) exit(0);

patch = get_kb_item ("SMB/KB823353");
if ( patch == TRUE ) exit (0);


version = get_kb_item ("SMB/OutlookExpress/MSOE.dll/Version");
if (!version)
  exit (0);

port = get_kb_item("SMB/transport");
if(!port) port = 139;

v = split (version, sep:".", keep:FALSE);

if ( v[0] == 5 )
	{
	 if ( (v[0] == 5 && v[1] < 50) || 
	      (v[0] == 5 && v[1] == 50 && v[2] < 4922) ||
	      (v[0] == 5 && v[1] == 50 && v[2] == 4922 && v[3] < 1500 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-013", value:TRUE);
 hotfix_security_hole();
 }}
	}
else if ( v[0] == 6 )
	{
	 if ( ( v[0] == 6 && v[1] == 0 && v[2] < 2720) ||
	      ( v[0] == 6 && v[1] == 0 && v[2] == 2720 && v[3] < 3000 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-013", value:TRUE);
 hotfix_security_hole();
 }}

	 else if ( ( v[0] == 6 && v[1] == 0 && v[2] > 2720 && v[2] < 2800) ||
	           ( v[0] == 6 && v[1] == 0 && v[2] == 2800 && v[3] < 1409 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-013", value:TRUE);
 hotfix_security_hole();
 }}

	 else if( ( v[0] == 6 && v[1] == 0 && v[2] > 2800 && v[2] < 3790 ) ||
	          ( v[0] == 6 && v[1] == 0 && v[2] == 3790 && v[3] < 137 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-013", value:TRUE);
 hotfix_security_hole();
 }}
	}

