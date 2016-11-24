#
# (C) Tenable Network Security, Inc.
#
#
# Default Account
#
# This file implements (or will implement) various ways of determining if
# an account is valid
#
#
# $Id: default_account.inc,v 1.22 2009/10/22 16:23:56 theall Exp $
#
# @NOGPL@
#

include('telnet_func.inc');
include('ssh_func.inc');


#
# Private functions
# 

function _check_telnet(port, login, password)
{
 local_var soc, res;
 soc = open_sock_tcp(port);
 if(!soc)return(0);

 res = telnet_negotiate(socket:soc);
 res += recv_until(socket:soc, pattern:"ogin:");
 if ( ! res ) exit(0, 'Login prompt was not found');

 send(socket:soc, data:login + '\r\n');
 if ( isnull(password) )
  {
   send(socket:soc, data:'id\r\n');
   res = recv_until(socket:soc, pattern:"uid=");
   close(soc);
   if ( res ) return 1; 
   else return 0;
  }


 res = recv_until(socket:soc, pattern:"word:");
 if ( res == NULL ) 
 {
  close(soc);
  return 0;
 }

 send(socket:soc, data:password + '\r\n');
 send(socket:soc, data:'id\r\n');
 
 res = recv_until(socket:soc, pattern:"uid=");
 close(soc);
 if ( res ) return 1;
 else return 0;

}

#-------------------------------------------------------------------#


function check_account(login, password)
{
 local_var port, ret, banner, soc, res;
 local_var payload;

 if (  get_kb_item("global_settings/supplied_logins_only") ) return 0;
 

 if ( defined_func("bn_random") )
 {
  # Prefer login thru SSH rather than telnet
  port = get_kb_item("Services/ssh");
  if ( ! port ) port = 22;
  banner = get_kb_item("SSH/banner/" + port);
  if (
    banner && 
    # GoodTech SSH server does not respect SSH protocol ...
    "cryptlib" >!< banner && 
    # nor does Mocana's (at least as used in AMX devices).
    "SSH-2.0-Mocana SSH" >!< banner
  ) 
  {
   _ssh_socket = open_sock_tcp(port);
   if ( _ssh_socket )
   {
   ret = ssh_login(login:login, password:password);
   if ( ret == 0 )
   {
    #
    # Some SSH servers do not fully respect the SSH protocol - they
    # claim that password authentication succeeded, but then 
    # they'll refuse any other command. The workaround here is to
    # open a SSH, as if we wanted to create an interactive session.
    #
    # Note that we do not use ssh_open_channel() but a stripped down version
    #
    payload = putstring(buffer:"session") + raw_int32(i:1) + raw_int32(i:32768) + raw_int32(i:32768);
    send_ssh_packet(payload:payload, code:raw_int8(i:90));
    payload = recv_ssh_packet();
    if ( !isnull(payload) )
    {
	# Fix for tectia AIX
	if (ord(payload[0]) == 95)
 	{
   	 payload = getstring(buffer:payload, pos:9);
      	 payload = recv_ssh_packet();
	}
	if ( !isnull(payload) && ord(payload[0]) == 91 )
	{
   	 ssh_close_connection();
	 return port;
	}
    }
   }
   ssh_close_connection();
   if ( ret == 0 ) return port;
   #else return 0; 
   }
  }
 }

 port = get_kb_item("Services/telnet");
 if(!port) port = 23;
 
 if(get_port_state(port))
 {
  if ( isnull(password) ) password = "";
  res = _check_telnet(port:port, login:login, password:password);
  if(res)
   return(port);
 }
 return(0);
}
