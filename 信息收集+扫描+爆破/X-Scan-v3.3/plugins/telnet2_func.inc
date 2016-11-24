# -*- Fundamental -*-
#
# 
# (C) 2007 Tenable Network Security, Inc
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# telnet2_func.inc 
# $Revision: 1.2 $
#


include ("byte_func.inc");


OPT_TERM_TYPE      = 24;   # Termninal Type
OPT_NEG_ABOUT_SIZE = 31;   # Negotiate About Size
OPT_ENV            = 36;   # Environment option
OPT_NEW_ENV        = 39;   # New Environment option

CMD_SE    = 240;  # End of subnegotiation parameters.
CMD_NOP   = 241;  # No operation.
CMD_DM    = 242;  # Data stream portion of a synch (TCP Urgent notification).
CMD_BREAK = 243;  # NVT character BRK.
CMD_IP    = 244;  # Interrupt Process
CMD_AO    = 245;  # Abort Output
CMD_AYT   = 246;  # Are You There
CMD_EC    = 247;  # Erase Character
CMD_EL    = 248;  # Erase Line
CMD_GA    = 249;  # Go Ahead
CMD_SB    = 250;  # Subnegotiation
CMD_WILL  = 251;
CMD_WONT  = 252;
CMD_DO    = 253;
CMD_DONT  = 254;
CMD_IAC   = 255;


NO_STATE  = 0;


global_var _tsock, _tport, _timeout, _time_start, _toptions;
global_var _terrno;


function telnet2_init (port, options, timeout)
{
 if (!isnull(port))
   _tport = port;
 else
 {
  _tport = get_kb_item("Services/telnet");
  if (!_tport)
    _tport = 23;
 }

 if (!get_port_state(_tport))
   return FALSE;

 _toptions = options;
 _timeout = timeout;
 _time_start = unixtime();

 _terrno = 0;
 _tsock = open_sock_tcp (_tport);
 if (!_tsock)
   return FALSE;

 return TRUE;
}


function telnet_read ()
{
 local_var len;

 if (max_index(_FCT_ANON_ARGS) > 0)
 {
  len = _FCT_ANON_ARGS[0];
  return recv(socket:_tsock, length:len);
 }

 return recv(socket:_tsock, length:1, min:1, timeout:0);
}


function telnet_write ()
{
 local_var data;
 data = _FCT_ANON_ARGS[0];

 send(socket:_tsock, data:data);
}


function telnet_send_cmd (cmd, data)
{
 telnet_write (mkbyte(CMD_IAC)+mkbyte(cmd)+data);
}


function telnet_wont ()
{
 local_var data;
 data = _FCT_ANON_ARGS[0];

 return telnet_send_cmd (cmd:CMD_WONT, data:data);
}


function telnet_dont ()
{
 local_var data;
 data = _FCT_ANON_ARGS[0];

 return telnet_send_cmd (cmd:CMD_DONT, data:data);
}


function telnet_will ()
{
 local_var data;
 data = _FCT_ANON_ARGS[0];

 return telnet_send_cmd (cmd:CMD_WILL, data:data);
}


function telnet_send_suboption (cmd, data)
{
 telnet_send_cmd (cmd:CMD_SB, data:mkbyte(cmd)+data);
 telnet_send_cmd (cmd:CMD_SE, data:NULL);
}


function telnet_do_term_type()
{
 local_var data;
 data = _FCT_ANON_ARGS[0];

 # if not "Sends your terminal type" (0x01)
 if (strlen(data) <= 0 || ord(data[0]) != 0x01)
   return;

 data = mkbyte(0) + # Here is my term type
	"XTERM";

 telnet_send_suboption (cmd:OPT_TERM_TYPE, data:data);
}


function telnet_do_neg_about_size()
{
 local_var data;
 data = _FCT_ANON_ARGS[0];

 data = mkword(126) + # Width
	mkword(49);   # Height

 telnet_send_suboption (cmd:OPT_NEG_ABOUT_SIZE, data:data);
}


function is_registered_option ()
{
 local_var opt, options, found;
 opt = _FCT_ANON_ARGS[0];

 found = FALSE;
 foreach options (_toptions)
 {
  if (opt == options[0])
  {
   found = TRUE;
   break;
  }
 }

 return found;
}


function get_registered_option ()
{
 local_var opt, options, found;
 opt = _FCT_ANON_ARGS[0];

 found = NULL;

 foreach options (_toptions)
 {
  if (opt == options[0])
  {
   found = options;
   break;
  }
 }

 return found;
}


function telnet_handle_suboption ()
{
 local_var opt, xtra, len, option;
 local_var data;
 data = _FCT_ANON_ARGS[0];

 len = strlen(data);

 if (len < 1)
   return;

 if (len > 1)
   xtra = substr(data, 1, len-1);
 else
   xtra = NULL;
 
 opt = ord(data[0]);

 option = get_registered_option(opt);

 if (option != NULL)
  telnet_send_suboption (cmd:opt, data:option[1]); 
 else if (opt == OPT_TERM_TYPE)
   telnet_do_term_type(xtra);
 else if (opt == OPT_NEG_ABOUT_SIZE)
   telnet_do_neg_about_size(xtra);
 
 return;
}



function telnet_loop ()
{
 local_var byte, cmd, state, _subneg;

 state = NO_STATE;

 while (1)
 {
  # checks timeout first
  if ((unixtime()-_time_start) >= _timeout)
  {
    _terrno = ETIMEDOUT;
    return;
  }

  byte = telnet_read();

  if (isnull(byte))
  {
   if ( telnet_callback() == -1 ) return;
   continue;
  }

  cmd = ord(byte[0]);

  # before parsing data we make sure it is not IAC
  if (cmd == CMD_IAC)
  {
   state = CMD_IAC;
   continue;
  }

  if (state == CMD_IAC)
  {
   if (cmd < CMD_SE || cmd > CMD_DONT)
   {
    state = NO_STATE;
    continue;
   }

   state = cmd;

   if (cmd >= CMD_WILL && cmd <= CMD_DONT)
     continue;

   if (cmd == CMD_SB)
   {
    _subneg = NULL;
    continue;
   }

   if (cmd == CMD_SE)
   {
    telnet_handle_suboption(_subneg);
    _subneg = NULL;
    continue;
   }

   # must take care of other commands here
   continue;
  }

  if (state == CMD_DO)
  {
   if (is_registered_option(cmd) || cmd == OPT_TERM_TYPE || cmd == OPT_NEG_ABOUT_SIZE)
     telnet_will(byte);
   else
     telnet_wont(byte);

   state = NO_STATE;
   continue;
  }

  if (state == CMD_DONT)
  {
   telnet_wont(byte);

   state = NO_STATE;
   continue;
  }

  if (state == CMD_WILL)
  {
   telnet_dont(byte);

   state = NO_STATE;
   continue;
  }

  if (state == CMD_SB)
  {
   _subneg += byte;
   continue;
  }

  if (state >= CMD_SE && state <= CMD_DONT)
  {
   state = NO_STATE;
   continue;
  }

  # we give the data to the callback function
  if ( telnet_callback(byte) == -1 ) return;
 }
}

