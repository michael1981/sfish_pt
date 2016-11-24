#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10135);
 script_version ("$Revision: 1.14 $");
 name["english"] = "LinuxConf Detection";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A LinuxConf server is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running LinuxConf, a web-based administration 
tool for Linux. It is suggested to not allow anyone to connect 
to this service." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port, or disable this service
if you do not use it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();

 
 summary["english"] = "Detects the presence of LinuxConf";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc."); 
 family["english"] = "Service detection";
 script_family(english:family["english"]);
 script_dependencies("httpver.nasl");
 script_require_ports("Services/linuxconf", 98);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/linuxconf");
if(!port)port = 98;
if (get_port_state(port))
{
 banner = http_get_cache(item:"/", port:port);
 version = egrep(pattern:"^Server: linuxconf/", string:version);
 if ( version )
 {
    version = ereg_replace(pattern:"^Server: linuxconf/(.*)$", string:version);
    report = 'nLinuxConf version : ' + version;
    security_note(port:port, extra:report);
    set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
 }
}
