#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10070);
 script_version ("$Revision: 1.24 $");

 script_xref(name:"OSVDB", value:"20");

 script_name(english:"Finger Backdoor Detection");
 script_summary(english:"Finger cmd_root@host backdoor");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote finger daemon appears to be a backdoor."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote finger daemon seems to be a backdoor, as it seems to react\n",
     "to the request :\n\n",
     "  cmd_rootsh@target\n\n",
     "If a root shell has been installed as /tmp/.sh, then this finger\n",
     "daemon is definitely a trojan, and this system has been compromised."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Audit the integrity of this system, since it seems to have been\n",
     "compromised"
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_family(english:"Backdoors");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/finger", 79);

 exit(0);
}

#
# The script code starts here
#


include('global_settings.inc');

if ( report_paranoia < 2 )exit(0);

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("root\r\n");
  send(socket:soc, data:buf);
  data_root = recv(socket:soc, length:2048);
  close(soc);
  if(data_root)
  {
   soc = open_sock_tcp(port);
   if(soc)
   {
    buf = string("cmd_rootsh\r\n");
    send(socket:soc, data:buf);
    data_cmd_rootsh = recv(socket:soc, length:2048);
    close(soc);

    if(!data_cmd_rootsh)
    {
     buf = string("version\r\n");
     soc = open_sock_tcp(port);
     if(!soc)exit(0);
     send(socket:soc, data:buf);
     data_version = recv(socket:soc, length:2048);
     close(soc);

     if("CFINGERD" >< data_version) exit(0); #false positive
     if((data_root == data_version)) exit(0); #false positive, same answer all the time
     security_hole(port);
    }
   }
  }
 }
}
