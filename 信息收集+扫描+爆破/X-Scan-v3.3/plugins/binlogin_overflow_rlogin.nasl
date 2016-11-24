#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
   script_id(10828);
   script_version("$Revision: 1.19 $");
   script_cve_id("CVE-2001-0797");
   script_bugtraq_id(3681);
   script_xref(name:"OSVDB", value:"691");
   script_xref(name:"IAVA", value:"2001-a-0014");

   script_name(english:"SysV /bin/login Environment Remote Overflow (rlogin)");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote /bin/login seems to crash when it receives too many
environment variables. This is likely due to a buffer overflow
vulnerability which might allow an attacker to execute arbitrary
code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.cert.org/advisories/CA-2001-34.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch from your vendor (or read the CERT advisory)" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();
 
  script_summary(english:"Attempts to overflow /bin/login");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/rlogin", 513);
  exit(0);
}


#
# The script code starts here
#

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/rlogin");
if(!port)port = 513;


function rlogin(env)
{
 local_var soc, s1, s2, a;
 global_var port;

if(get_port_state(port))
{
 soc = open_priv_sock_tcp(dport:port);
 if(soc)
 {
  s1 = raw_string(0);
  s2 = string("nessus", s1, s1);
  send(socket:soc, data:s1);
  send(socket:soc, data:s2);
 
  a = recv(socket:soc, length:1, min:1);
 
  
  if(!strlen(a)){
  	return(0);
	}
  if(!(ord(a[0]) == 0)){
  	return(0);
	}
  send(socket:soc, data:s1);
  a = recv(socket:soc, length:1024, min:1);
  if("ogin:" >< a)
  {
    send(socket:soc, data:string(env, "\r\n"));
    a = recv(socket:soc, length:4096);
    a = recv(socket:soc, length:4096);
    if("word:" >< a)
    {
     close(soc);
     return(1);
    }
   }
   close(soc);
  }
  else return(0);
 }
 return(0);
}


if(rlogin(env:"nessus"))
{
res = rlogin(env:string("nessus ", crap(data:"A=B ", length:244)));
if(res)
 {
  res = rlogin(env:string("nessus ", crap(data:"A=B ", length:400)));
  if(!res)security_hole(port);
 }
}
