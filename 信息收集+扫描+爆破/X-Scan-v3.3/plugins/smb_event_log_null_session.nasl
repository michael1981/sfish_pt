#
# (C) Tenable Network Security, Inc.
#

#
# Thanks to: Jean-Baptiste Marchand of Hervé Schauer Consultants
#

include( 'compat.inc' );

if(description)
{
  script_id(18602);
  script_version ("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2150");
  script_bugtraq_id(14093, 14178);
  script_xref(name:"OSVDB", value:"17860");

  script_name(english:"SMB OpenEventLog() over \srvsvc");
  script_summary(english:"Enumerates the list of remote services");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote host allows null session event log reading."
  );

  script_set_attribute(
    attribute:'description',
    value:
"It is possible to anonymously read the event logs of the remote
Windows 2000 host by connecting to the \srvsvc pipe and binding to the
event log service. 

An attacker may use this flaw to anonymously read the system logs of
the remote host.  As system logs typically include valuable
information, an attacker may use them to perform a better attack
against the remote host."
  );

  script_set_attribute(
    attribute:'solution',
    value:
"Install the Update Rollup Package 1 (URP1) for Windows 2000 SP4 or
set the value RestrictGuestAccess on the Applications and System
logs."
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-07/0137.html"
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

function OpenEventLog_crafted ()
{
 local_var fid, ret, data, type, resp, rep;

 fid = bind_pipe (pipe:"\srvsvc", uuid:"82273fdc-e32a-18c3-3f78-827929dc23ea", vers:0);
 if (isnull (fid))
   return NULL;

 if (session_is_unicode ())
 {
  type = 7;
  data = raw_string (
	0xC8, 0x46, 0x42, 0x00, 0x31, 0x00, 0x01, 0x00, 0x16, 0x00, 0x18, 0x00, 0x38, 0x41, 0x42, 0x00,
	0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x41, 0x00, 0x70, 0x00,
	0x70, 0x00, 0x6C, 0x00, 0x69, 0x00, 0x63, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00,
	0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00 );
 }
 else
 {
  type = 14;
  data = raw_string (
	0x40, 0x41, 0x42, 0x00, 0x31, 0x00, 0x01, 0x00, 0x0B, 0x00, 0x0C, 0x00, 0x14, 0x42, 0x42, 0x00,
	0x0C, 0x00, 0x00, 0x00, 0x41, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x00,
	0x0B, 0x00, 0x0C, 0x00, 0xC4, 0x69, 0xDE, 0x77, 0x0C, 0x00, 0x00, 0x00, 0x41, 0x70, 0x70, 0x6C,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 );
 }

 data = dce_rpc_pipe_request (fid:fid, code:type, data:data);
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

os = get_kb_item ("Host/OS/smb") ;
if ( "Windows 5.0" >!< os ) exit(0);

port = int(get_kb_item("SMB/transport"));
if (!port) port = 445;

name = kb_smb_name();
if(!name)exit(0);

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (share:"IPC$");
if (ret != 1)
{
 close (soc);
 exit (0);
}

ret = OpenEventLog_crafted();
if (!isnull(ret))
   security_warning( port );


NetUseDel();
