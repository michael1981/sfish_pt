#
# This script was written by Javier Fernandez-Sanguino
# based on a script written by Renaud Deraison <deraison@cvs.nessus.org>
# with contributions by Gareth M Phillips <gareth@sensepost.com> (additional logins and passwords)
#
# GPLv2
# 
# TODO:
# - dump the device configuration to the knowdledge base (requires
#   'enable' access being possible)
# - store the CISCO IOS release in the KB so that other plugins (in the Registered
#   feed) could use the functions in cisco_func.inc to determine if the system is
#   vulnerable as is currently done through SNMP (all the CSCXXXX.nasl stuff)
# - store the user/password combination in the KB and have another plugin test
#   for common combinations that lead to 'enable' mode.
#


include("compat.inc");

if(description) 
{
 script_id(23938);
 script_version ("$Revision: 1.15 $");

 script_cve_id("CVE-1999-0508");

 script_name(english:"Cisco Device Default Password");


 summary["english"] = "Checks for a default password";
 script_summary(english:summary["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote device has a factory password set." );
 script_set_attribute(attribute:"description", value:
"The remote CISCO router has a default password set. This allows an 
attacker to get a lot information about the network, and possibly to
shut it down if the 'enable' password is not set either or is also a 
default password." );
 script_set_attribute(attribute:"solution", value:
"Access this device and set a password using 'enable secret'" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001-2009 Javier Fernandez-Sanguino and Renaud Deraison");

 script_family(english:"CISCO");
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

include('telnet_func.inc');
include('ssh_func.inc');
include('global_settings.inc');

if ( supplied_logins_only ) exit(0);

global_var ssh_port, telnet_checked, telnet_port;

# Function to connect to a Cisco system through telnet, send
# a password

function check_cisco_telnet(login, password, port)
{
 local_var msg, r, soc, report;

 soc = open_sock_tcp(port);
 if ( ! soc )
 	{
	  telnet_port = 0;
	  return;
	}
 msg = telnet_negotiate(socket:soc, pattern:"(ogin:|asscode:|assword:)");

 if(strlen(msg))
 {
  # The Cisco device might be using an AAA access model
  # or have configured users:
  if ( stridx(msg, "sername:") != -1 || stridx(msg, "ogin:") != -1  )  {
    send(socket:soc, data:string(login, "\r\n"));
    msg=recv_until(socket:soc, pattern:"(assword:|asscode:)");
  }

  # Device can answer back with {P,p}assword or {P,p}asscode
  # if we don't get it then fail and close
  if ( strlen(msg) == 0 || (stridx(msg, "assword:") == -1 && stridx(msg, "asscode:") == -1)  )  {
    close(soc);
    return(0);
  }

  send(socket:soc, data:string(password, "\r\n"));
  r = recv(socket:soc, length:4096);

  # TODO: could check for Cisco's prompt here, it is typically
  # the device name followed by '>'  
  # But the actual regexp is quite complex, from Net-Telnet-Cisco:
  #  '/(?m:^[\r\b]?[\w.-]+\s?(?:\(config[^\)]*\))?\s?[\$\#>]\s?(?:\(enable\))?\s*$)/')
  
  # Send a 'show ver', most users (regardless of privilege level)
  # should be able to do this
  send(socket:soc, data:string("show ver\r\n"));
  r = recv_until(socket:soc, pattern:"(Cisco (Internetwork Operating System|IOS) Software|assword:|asscode:|ogin:|% Bad password)");

  # TODO: This is probably not generic enough. Some Cisco devices don't 
  # use IOS but CatOS for example

  # TODO: It might want to change the report so it tells which user / passwords
  # have been found
  if(
     strlen(r) &&
     "Cisco Internetwork Operating System Software" >< r ||
     "Cisco IOS Software" >< r
  ) 
  {
    report = '\n\nPlugin Output :\n\nIt was possible to log in as \'' + login + '\'/\'' + password + '\'\n';
    security_hole(port:port, extra:report);
    exit(0);
  }

# TODO: it could also try 'enable' here and see if it's capable
# of accessing the priviledge mode with the same password, or do it
# in a separate module

  close(soc);

 }
}

# Functions modified from the code available from default_accounts.inc
# (which is biased to UNIX)
function check_cisco_account(login, password)
{
 local_var port, ret, banner, soc, res, report;


 if ( ssh_port )
 {
  # Prefer login thru SSH rather than telnet
   _ssh_socket= open_sock_tcp(ssh_port);
   if ( _ssh_socket)
   {
   ret = ssh_login(login:login, password:password);
   close(_ssh_socket);
   if ( ret == 0 ) {
	report = '\n\nPlugin Output :\n\nIt was possible to log in as \'' + login + '\'/\'' + password + '\'\n';
	security_hole(port:ssh_port, extra:report);
	exit(0);
	}
   else return 0;
   }
   else
     ssh_port = 0;
 }


 if(telnet_port && get_port_state(telnet_port))
 {
  if ( isnull(password) ) password = "";
  if ( ! telnet_checked ) 
  {
  banner = get_telnet_banner(port:telnet_port);
  if ( banner == NULL ) { telnet_port = 0 ; return 0; }
  # Check for banner, covers the case of Cisco telnet as well as the case
  # of a console server to a Cisco port
  # Note: banners of cisco systems are not necesarily set, so this
  # might lead to false negatives !
  if ( stridx(banner,"User Access Verification") == -1 && stridx(banner,"assword:") == -1)  
    {
     telnet_port = 0;
     return(0);
    }
   telnet_checked ++;
  }
  
  check_cisco_telnet(login:login, password:password, port:telnet_port);
 }
 return(0);
}


# SSH disabled for now
#ssh_port = get_kb_item("Services/ssh");
#if ( ! ssh_port ) ssh_port = 22;


telnet_port = get_kb_item("Services/telnet");
if ( ! telnet_port ) telnet_port = 23;

telnet_checked = 0;

check_cisco_account(login:"cisco", password:"cisco");
check_cisco_account(login:"", password:"");
if ( safe_checks() == 0 )
{
 check_cisco_account(login:"cisco", password:"");
 check_cisco_account(login:"admin", password:"cisco");
 check_cisco_account(login:"admin", password:"diamond");
 check_cisco_account(login:"admin", password:"admin");
 check_cisco_account(login:"admin", password:"system");
 check_cisco_account(login:"monitor", password:"monitor");
}

