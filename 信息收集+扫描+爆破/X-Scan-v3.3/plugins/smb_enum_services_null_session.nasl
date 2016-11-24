#
# (C) Tenable Network Security, Inc.
#

#
# Thanks to: Jean-Baptiste Marchand of Hervé Schauer Consultants
#

include( 'compat.inc' );

if(description)
{
  script_id(18585);
  script_cve_id("CVE-2005-2150");
  script_bugtraq_id(14093, 14177);
  script_version ("$Revision: 1.10 $");
  script_xref(name:"OSVDB", value:"17859");

  script_name(english:"SMB enum services over \srvsvc");
  script_summary(english:"Enumerates the list of remote services");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote host allows null session enumeration of running services."
  );

  script_set_attribute(
    attribute:'description',
    value:"This plugins connects to \srvsvc (instead of \svcctl) to enumerate
the list of services running on the remote host on top of
a NULL session.

An attacker may use this feature to gain better
knowledge of the remote host."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Install the Update Rollup Package 1 (URP1) for Windows 2000 SP4"
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://www.hsc.fr/ressources/presentations/null_sessions/"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("smb_enum_services.nasl", "smb_nativelanman.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");

function OpenSCManager_SRVSVC (access_mode)
{
 local_var fid, ret, data, type, resp, rep, name, opnum;

 fid = bind_pipe (pipe:"\srvsvc", uuid:"367abb81-9844-35f1-ad32-98f038001003", vers:2);
 if (isnull (fid))
   return NULL;

 if (session_is_unicode() == 1)
   opnum = OPNUM_OPENSCMANAGERW;
 else
   opnum = OPNUM_OPENSCMANAGERA;

 data = raw_dword (d:0x0020000)                       + # ref_id
        class_name (name:"\\"+session_get_hostname()) +
        raw_dword (d:0)                               + # NULL database pointer
        raw_dword (d:access_mode) ;                     # Desired Access

 data = dce_rpc_pipe_request (fid:fid, code:opnum, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;

 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = fid;
 ret[2] = 1;

 return ret;
}






os = get_kb_item("Host/OS/smb");
if ( "Windows 5.0" >!< os ) exit(0);

port = kb_smb_transport();
if(!port)port = 139;


# Does not work against Samba
smb = get_kb_item("SMB/samba");
if(smb)exit(0);


name = kb_smb_name();
if(!name)return(FALSE);

if(!get_port_state(port))return(FALSE);

soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (login:"", password:"", domain:"", share:"IPC$");
if (ret != 1)
{
 close (soc);
 exit (0);
}


# Can we access \svcctl ?
pipe = "\svcctl";
handle = OpenSCManager(access_mode:SC_MANAGER_ENUMERATE_SERVICE);
if ( isnull(handle) )
{
 pipe = "\srvsvc";
 # Can we access \srvsvc ?
 handle = OpenSCManager_SRVSVC (access_mode:SC_MANAGER_ENUMERATE_SERVICE);
 if (isnull (handle))
 {
  NetUseDel();
  exit (0);
 }
}

list = EnumServicesStatus (handle:handle, type:SERVICE_WIN32, state:SERVICE_ACTIVE);

CloseServiceHandle (handle:handle);
NetUseDel ();

if (isnull (list))
  exit (1);

services = NULL;

foreach elem (list)
{
 parse = GetService (service:elem);
 services += parse[1] + " [ " + parse[0] + ' ] \n';
}


if(services)
{
 if ( ! get_kb_item("SMB/svcs") )
 	set_kb_item(name:"SMB/svcs", value:services);

 head = "
It was possible to enumerate the list of services running on the remote
host thru a NULL session, by connecting to " + pipe + "


Here is the list of services running on the remote host :
";

 moral = "
Solution : Install the Update Rollup Package 1 (URP1) for Windows 2000 SP4
Risk factor : Low";
 services = head + services + moral;
 security_warning(extra:services, port:port);
}
