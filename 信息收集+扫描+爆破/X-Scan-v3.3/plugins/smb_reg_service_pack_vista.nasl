#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(38912);
  script_version("$Revision: 1.3 $");
  
  script_name(english:"SMB Registry : Windows Vista / Server 2008 Service Pack Detection");
  script_summary(english:"Determines the remote SP");
 script_set_attribute(attribute:"synopsis", value:
"It was possible to determine the service pack installed on 
the remote system." );
 script_set_attribute(attribute:"description", value:
"It is possible to determine the Service Pack version of the Windows
Vista / Server 2008 system by reading the registry key
'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CDSVersion'." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

port = get_kb_item("SMB/transport");
if(!port) port = 139;
win = get_kb_item("SMB/WindowsVersion");
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

if(win == "6.0" )
{
  if (ereg(pattern:"Service Pack [1-9]", string:sp))
  {
    set_kb_item(name:"SMB/Vista/ServicePack", value:sp);
    report = string("\n",
      "The remote Windows Vista / Server 2008 system has ",sp," applied,\n",
      "\n"
    );
    security_note(port:port, extra:report);
    exit(0);
  }
}
