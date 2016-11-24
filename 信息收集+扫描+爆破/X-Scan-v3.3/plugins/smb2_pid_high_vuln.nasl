#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40887);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2009-3103");
  script_bugtraq_id(36299);
  script_xref(name:"OSVDB", value:"57799");

  script_name(english:"MS09-050: Microsoft Windows SMB2 _Smb2ValidateProviderCallback() Vulnerability (975497) (uncredentialed check)");
  script_summary(english:"Determines if the remote host is vulnerable to a SMBv2 vulnerability");

  script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be executed on the remote host through the SMB port");
  script_set_attribute(attribute:"description", value: "
The remote host is running a version of Microsoft Windows Vista or
Windows Server 2008 which contains a vulnerability in its SMBv2
implementation. 

An attacker could exploit this flaw to disable the remote host or to
execute arbitrary code on it.");

 script_set_attribute(attribute:"solution", value:"
Microsoft has released a patch for Windows Vista and Windows Server 2008 :

http://www.microsoft.com/technet/security/Bulletin/MS09-050.mspx");

  script_set_attribute(attribute:"see_also", value:"http://g-laurent.blogspot.com/2009/09/windows-vista7-smb20-negotiate-protocol.html");
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/08"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/08"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/13"
  );

  script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_require_ports(445);
  exit(0);
}

#

include("smb_func.inc");

port = 445;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
session_set_socket(socket:soc);


#---------------------------------------------------------#
# struct {                                                #
#   BYTE  Protocol[4];      # "\xFFSMB"                   #
#   BYTE  Command;                                        #
#   DWORD Status;           # Or BYTE ErrorClass;         #
#                           #    BYTE Reserved;           #
#                           #    WORD Error;              #
#   BYTE  Flags;                                          #
#   WORD  Flags2;                                         #
#   WORD  PidHigh;          			          #
#   BYTE  Signature[8];                                   #
#   WORD  Reserved;                                       #
#   WORD  Tid;              # Tree ID                     #
#   WORD  Pid;              # Process ID                  #
#   WORD  Uid;              # User ID                     #
#   WORD  Mid;              # Multiplex ID                #
# }                                                       #
#---------------------------------------------------------#


header = '\xFFSMB'; 
header += raw_byte(b:SMB_COM_NEGOTIATE);
header += nt_status(Status:STATUS_SUCCESS);
header += raw_byte (b:0x18);
header += raw_word (w:0xc853);
header += raw_word(w:0x0001); # Process ID high
header += raw_dword (d:session_get_sequencenumber()) + raw_dword (d:0);
header += raw_word (w:0);
header += raw_word (w:session_get_tid());
header += raw_word (w:session_get_pid());
header += raw_word (w:session_get_uid());
header += raw_word (w:session_get_mid());

parameters = smb_parameters(data:NULL);

ns = supported_protocol;

protocol[0] = "TENABLE_NETWORK_SECURITY";
data = NULL;
for (i = 0; i < ns; i++)
  data += raw_byte (b:0x02) + ascii (string:protocol[i]);
data = smb_data (data:data);


packet = netbios_packet (header:header, parameters:parameters, data:data);

r = smb_sendrecv(data:packet);
close(soc);

if ( !isnull(r) && "ORK_SECURITY" >< r )
	security_hole(port);
else exit(0, "The remote host is not vulnerable to this flaw");
