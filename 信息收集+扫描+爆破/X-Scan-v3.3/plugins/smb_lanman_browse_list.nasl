#
# (C) Tenable Network Security, Inc.
#
# This script is released under Tenable Plugins License
#


include("compat.inc");

if(description)
{
 script_id(10397);
 script_version ("$Revision: 1.28 $");
 script_xref(name:"OSVDB", value:"300");
 name["english"] = "SMB LanMan Pipe Server browse listing";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain network information." );
 script_set_attribute(attribute:"description", value:
"It was possible to obtain the browse list of the remote Windows system
by send a request to the LANMAN pipe.  The browse list is the list of
the nearest Windows systems of the remote host." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
 summary["english"] = "Gets the list of remote host browse list";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

function create_list (data)
{
 local_var comment, i, list, name, server;

 list = NULL;

 foreach server (data)
 {
  name = NULL;
  for (i=0;i<16;i++)
  {
   if (ord(server[i]) == 0)
     break;
   name += server[i];
  }

  if (strlen(server) > 26)
    comment = " - " + substr(server,26,strlen(server)-1);
  else
    comment = "";

  list += name + string (" ( os : ", ord(server[16]), ".", ord(server[17]), " )",comment,"\n"); 
 }

 return list;
}

port = kb_smb_transport();
if(!port)port = 139;

name = kb_smb_name();
if(!name)exit(0);

if(!get_port_state(port))exit(0);

login = kb_smb_login();
pass = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";
	  
dom = kb_smb_domain();
if (!dom) dom = "";
  
soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init (socket:soc,hostname:name,smb2:FALSE);
ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
{
 close (soc);
 exit (0);
}

#
# Request the list of shares
#
servers = NetServerEnum (level:SERVER_INFO_101);
NetUseDel ();
if(!isnull(servers))
{
 # decode the list
 browse = create_list(data:servers);
 if(browse)
 {
  # display the list
  res = string("Here is the browse list of the remote host : \n\n");
  res = res + browse;
  report = string ("\n", res);

  security_note(port:port, extra:report);
  set_kb_item(name:"SMB/browse", value:browse);
 }
}
