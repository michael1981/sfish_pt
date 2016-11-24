#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(10785);
 script_version ("$Revision: 1.32 $");
 name["english"] = "SMB NativeLanMan";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain information about the remote operating
system." );
 script_set_attribute(attribute:"description", value:
"It is possible to get the remote operating system name and
version (Windows and/or Samba) by sending an authentication
request to port 139 or 445." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );


script_end_attributes();

 
 summary["english"] = "Extracts the remote native lan manager name";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "samba_detect.nasl");
 script_require_ports(139,445, "/tmp/settings");
 exit(0);
}

include ("smb_func.inc");

port = kb_smb_transport();

if ( get_kb_item("Host/scanned") && ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

name	= kb_smb_name();
session_init(socket:soc, hostname:name, smb2:FALSE);

r = NetUseAdd(share:"IPC$");
if (r == 1)
  NetUseDel();

if (!isnull(Session[17]))
{
  report = string(
		"The remote Operating System is : ", Session[17],
		"\nThe remote native lan manager is : ", Session[18],
		"\nThe remote SMB Domain Name is : ", Session[19], "\n"
		);
  
  if (!get_kb_item("SMB/workgroup") && Session[19] )
  {
   set_kb_item (name:"SMB/workgroup", value:Session[19]);
  }

  if ( Session[18] )
   set_kb_item(name:"SMB/NativeLanManager", value:Session[18]);

  os = Session[17];
  if ("Windows NT" >< os)
    os = "Windows 4.0";
  else if ("Windows Server 2003" >< os)
    os = "Windows 5.2";
  else if ("Vista" >< os)
    os = "Windows 6.0";

 if ( os ) 
  set_kb_item(name:"Host/OS/smb", value:os);

  security_note(port:port, extra:report);
}
