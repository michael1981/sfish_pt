#
# (C) Tenable Network Security, Inc.
#

#
# Sun's patch makes /bin/login exits when it receives too many arguments,
# hence making the detection of the flaw difficult. Our logic is the
# following :
#
# Username: "nessus" -> should not crash
# Username: "nessus A=B..... x 61"  -> should not crash
# Username: "nessus A=B..... x 100" -> should crash
#


include("compat.inc");

if (description) {
   script_id(10827);
   script_version("$Revision: 1.21 $");
   script_cve_id("CVE-2001-0797");
   script_bugtraq_id(3681, 7481);
   script_xref(name:"OSVDB", value:"690");
   script_xref(name:"IAVA", value:"2001-a-0014");
   script_xref(name:"IAVA", value:"2002-A-0004");

   script_name(english:"SysV /bin/login Environment Remote Overflow (telnet check)");
 
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
  script_require_ports("Services/telnet", 23);
  exit(0);
}


include("global_settings.inc");
include('telnet_func.inc');

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/telnet");
if(!port) port = 23;
if(!get_port_state(port))exit(0);

function login(env, try)
{
  local_var	i, soc, r, buffer;

  # if (try <= 0) try = 1;
  for (i = 0; i < try; i ++)
  {
    sleep(i);
    soc = open_sock_tcp(port);
    if (soc) break;
  }

   if (soc)
   {

 buffer = telnet_negotiate(socket:soc);
 send(socket:soc, data:string("nessus ", env, "\r\n"));
 r = recv(socket:soc, length:4096);
 close(soc);
 if("word:" >< r)
  {
	return(1);
  }
 }
 return(0);
}



if(login(env:"", try: 1))
{
 my_env = crap(data:"A=B ", length:244);
 res = login(env:my_env);
 if(res)
 {
  my_env = crap(data:"A=B ", length:400);
  res = login(env:my_env, try: 4);
  if(!res)security_hole(port);
 }
}
