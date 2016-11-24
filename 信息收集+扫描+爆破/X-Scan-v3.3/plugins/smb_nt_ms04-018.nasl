#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(13643);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2004-0215");
 script_bugtraq_id(10711);
 script_xref(name:"OSVDB", value:"7793");

 name["english"] = "MS04-018: Cumulative Security Update for Outlook Express (823353)";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote email client." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing a cumulative security update for Outlook
Express that fixes a denial of service vulnerability in the Outlook
Express mail client. 

To exploit this vulnerability, an attacker would need to send a
malformed message to a victim on the remote host.  The message will
crash her version of Outlook, thus preventing her from reading her
e-mail." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook Express :

http://www.microsoft.com/technet/security/bulletin/ms04-018.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for ms04-018 over the registry";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms05-030.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( get_kb_item("SMB/897715") ) exit(0);
if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB823353") <= 0 ) exit(0);
if ( hotfix_missing(name:"KB823353") <= 0 ) exit(0);


version = get_kb_item ("SMB/OutlookExpress/MSOE.dll/Version");
if (!version)
  exit (0);

port = get_kb_item("SMB/transport");
if(!port) port = 139;

v = split (version, sep:".", keep:FALSE);
flag = 0;

if ( v[0] == 5 )
	{
	 if ( (v[0] == 5 && v[1] < 50) || 
	      (v[0] == 5 && v[1] == 50 && v[2] < 4942) ||
	      (v[0] == 5 && v[1] == 50 && v[2] == 4942 && v[3] < 400 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-018", value:TRUE);
 hotfix_security_warning();
 }flag ++; }
	}
else if ( v[0] == 6 )
	{
	 if ( ( v[0] == 6 && v[1] == 0 && v[2] < 2742) ||
	      ( v[0] == 6 && v[1] == 0 && v[2] == 2742 && v[3] < 2600 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-018", value:TRUE);
 hotfix_security_warning();
 }flag ++; }

	 else if ( ( v[0] == 6 && v[1] == 0 && v[2] > 2742 && v[2] < 2800) ||
	           ( v[0] == 6 && v[1] == 0 && v[2] == 2800 && v[3] < 1437 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-018", value:TRUE);
 hotfix_security_warning();
 }flag ++; }

	 else if( ( v[0] == 6 && v[1] == 0 && v[2] > 2800 && v[2] < 3790 ) ||
	          ( v[0] == 6 && v[1] == 0 && v[2] == 3790 && v[3] < 181 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-018", value:TRUE);
 hotfix_security_warning();
 }flag ++; }
	}

if ( flag == 0)
  set_kb_item (name:"SMB/KB823353", value:TRUE);
