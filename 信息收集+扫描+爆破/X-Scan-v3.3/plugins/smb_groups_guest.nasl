#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(10907);
 script_version("$Revision: 1.11 $");
 name["english"] = "Guest belongs to a group";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The 'Guest' account has excessive privileges." );
 script_set_attribute(attribute:"description", value:
"Using the supplied credentials, it is possible to determine that the
'Guest' user belongs to groups other than 'Guest Users' or 'Domain
Guests'.  Guest users should not have any additional privileges." );
 script_set_attribute(attribute:"solution", value:
"Edit the local or domain policy to restrict group membership for the
guest account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks the groups of guest";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : User management";
 script_family(english:family["english"]);
 script_dependencies("smb_sid2user.nasl", "smb_sid2localuser.nasl");
 script_require_ports (139,445);
 exit(0);
}

include ("smb_func.inc");

guest_dom = get_kb_item ("SMB/Users/2");
guest_host = get_kb_item ("SMB/LocalUsers/2");

name	= kb_smb_name();
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

if (guest_host)
  aliases = NetUserGetLocalGroups (user:guest_host);

if (guest_dom)
  groups = NetUserGetGroups (user:guest_dom);

NetUseDel();

if(!isnull(groups))
{
 foreach group ( groups )
 {
  if ( group != 514 && group != 513 )
  {
   security_hole(0);
   exit(0);
  }
 } 
}

if(!isnull(aliases))
{
 foreach alias ( aliases )
 {
  if ( alias != 546 ) 
  {
   security_hole(0);
   exit(0);
  }
 }
}
