#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25656);
 script_version("$Revision: 1.4 $");
 name["english"] = "IBM Tivoli Storage Manager Service";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A backup agent is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IBM Tivoli Storage Manager Agent, a backup
and data protection server." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
 summary["english"] = "Detects IBM Tivoli Storage Manager Agent";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Service detection";
 script_family(english:family["english"]);
 
 script_dependencie("find_service2.nasl");
 script_require_ports(1500);
 exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");



function send_verb (socket, code, data)
{
 local_var header, req;

 header = 
	mkbyte(0) +
	mkbyte(strlen(data)+4) +
	mkbyte(code) +
	mkbyte(0xa5);  # magic

 req = header + data;

 send(socket:socket, data:req);
}


function recv_verb(socket, code)
{
 local_var header, data, len;

 header = recv(socket:socket, length:4, min:4, timeout:10);
 if (isnull(header))
   return NULL;

 # checks magic byte
 if (ord(header[3]) != 0xa5)
   return NULL;

 # check response code
 if (ord(header[2]) != 0x1e)
   return NULL;

 len = ord(header[1]);
 if (len < 4)
   return NULL;

 len = len - 4;

 data = recv(socket:socket, length:len, min:len, timeout:10);

 return data;
}



port = 1500;

if (!service_is_unknown(port:port))
  exit(0);

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

send_verb(socket:soc, code:0x1d, data:NULL);
resp = recv_verb(socket:soc, code:0x1e);

len = strlen(resp);

if (len < 41)
  exit(0);

len1 = getword(blob:resp, pos:13);
len2 = getword(blob:resp, pos:15);

version = getword(blob:resp, pos:17);
release = getword(blob:resp, pos:19);
level = getword(blob:resp, pos:21);
sub_level = getword(blob:resp, pos:23);

flag = ord(resp[29]);

hostname = osname = NULL;

if (len >= (41 + len1 + len2))
{
 hostname = substr(resp, 41, 41+len1-1);
 osname = substr(resp, 41+len1, 41+len1+len2-1);
}

info = string(
	"version: ", version ,"\n",
	"release: ", release, "\n",
	"level: ", level, "\n",
	"sub_level: ", sub_level, "\n",
	"hostname: ", hostname, "\n",
	"osname: ", osname
	);


report = string ("\n",
		"The remote server version is :\n",
		info);

security_note(port:port, extra:report);


register_service (port:port, proto:"tsm-agent");
set_kb_item(name:"IBM/TSM/Version", value:string(version,".",release,".",level,".",sub_level));

if (flag & 0x08)
  set_kb_item(name:"IBM/TSM/isExpress", value:TRUE);
