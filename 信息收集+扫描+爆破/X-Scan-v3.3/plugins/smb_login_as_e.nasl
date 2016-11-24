#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11839);
  script_bugtraq_id(8459);
  script_version ("$Revision: 1.12 $");
  script_cve_id("CVE-2003-0528");
  script_xref(name:"OSVDB", value:"2535");

  script_name(english:"Possible Compromise through a vulnerability in RPC");
  script_summary(english:"Logs in as 'e'/'asd#321'");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote host has evidence of being compromised by a widely known exploit."
  );

  script_set_attribute(
    attribute:'description',
    value:"It was possible to log into the remote host with the login 'e' and
the password 'asd#321'.

A widely available exploit, using one of the vulnerabilities described
in the Microsoft Bulletin MS03-039 creates such an account. This probably
mean that the remote host has been compromised by the use of this exploit."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Re-install this host, as it has been compromised"
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://www.microsoft.com/technet/security/bulletin/ms03-039.mspx"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C'
  );

  script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("smb_login.nasl");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("global_settings.inc");

if ( supplied_logins_only ) exit(0);

if(get_kb_item("SMB/any_login"))exit(0);

login = "e";
pass  = "asd#321";

port = kb_smb_transport();
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login + string(rand()), password:pass + string(rand()), domain:NULL, share:"IPC$");
NetUseDel();
if ( r == 1 )  exit(1);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:NULL, share:"IPC$");
if ( r == 1 ) security_hole(port);
NetUseDel();
