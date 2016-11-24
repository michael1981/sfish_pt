#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10395);
 script_version ("$Revision: 1.34 $");
 name["english"] = "SMB shares enumeration";
 
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"It is possible to enumerate remote network shares." );
 script_set_attribute(attribute:"description", value:
"By connecting to the remote host, Nessus was able to enumerate 
the network share names." );
 script_set_attribute(attribute:"solution", value:"N/A" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 
 summary["english"] = "Gets the list of remote shares";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl","smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name");
 script_require_ports(139, 445);
 exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

max_shares = 100;

port = kb_smb_transport();
if(!port)port = 139;

name = kb_smb_name();
if(!name)exit(0);

if(!get_port_state(port))exit(0);

login = kb_smb_login();
pass = kb_smb_password();
dom = kb_smb_domain();
if ( ! login )
{
 login = pass = dom = NULL;
 if ( !supplied_logins_only && get_kb_item("SMB/any_login") ) 
 {
   login = "Nessus" + rand();
   pass = "Nessus" + rand();
 }
}

soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1) exit (0);
shares = NetShareEnum (level:SHARE_INFO_0);
if ( NetUseDel () < 0 ) close(soc);
if ( ! isnull(shares) ) 
  {
    res = NULL;
    nshares = 0;
    foreach share (shares) 
    {
      nshares++;
      if (nshares <= max_shares)
      {
        set_kb_item(name:"SMB/shares", value:share);
        res = res + '  - ' + share + '\n';
      }
    }

   if ( login == NULL ) login = "a NULL session";
   if ( nshares != 0 )
   {
     if (nshares <= max_shares)
     {
     report = string(
   "\n",
   "Here are the SMB shares available on the remote host when logged as ", login, ":\n",
   "\n",
   res
  );
    }
 else
   {
    report = string(
   "\n",
   nshares, " SMB shares are available on the remote host when logged as ", login, ".\nHere are the first ", max_shares, " :\n",
   "\n",
   res
   );
   }
  security_note(port:port, extra:report);
  }
 }
