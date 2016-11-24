#TRUSTED 05283264475adac4a495f7acfbaa707e3996b82a5da6070864c69a2cd3916173377cdcc3b20baaa71cca2047a41570ca232034feb6a1f61c93173082c40f179b682258f4fc4d62e791bac35fe2b4ef493ca99232ad46412281c273a15e88ce4c6370113814cb5eab03371d9e1490dd9f28625e557be1c5c0d761be43266dca9b10998d7d3f18c380a7220b2ae0f7c012b26a81c11cd0c9a28e3850fd01b4dbbbbe46e8dec254c9748e2d8521862cfcc2a870be8ce8d28688105e5c02b6d62b1800fb6a150b1f8c41f74fca92f183cd82539bb91243bd85ca7d456e1f5e634eb8646df9ef6ee7637526e0d2c6a1af76f4af28cbbc8dd34baeb558a22a37d080d398456ea2b983272be04e430b81d127956d4ff3bd987aadf2642b870236468201fb33f18308776db4618570d2f47476a9d2c9503ed4c25bcddcc432df4729ff6b216e5b0db7f02eb18e8c7f7f9103b4e9a6253af81221e5c590f2a78b197b6ff74878d3a1dcb85527c1064cd0c05ded61403ec66f9ed2d0f346ba511685a18f4a757650351dcfabe5f212a6f4ba38f2c529b4eb804aca7def9f911e37947dc5c398d4c37fa426de87f566c38bc67f788c1f53e6bf1a9154b922d72bfc0be87a34e03f20b0513c15fdc9b0a53d05162745b9109648c45c9a8d4e788bb2df2b8d325ba821ebf02bd8c16a071ec389faac119cff99411aca521585f0a9fae827ca53
#
# (C) Tenable Network Security, Inc.
#
# Version 1.10
#
# @NOGPL@
#


global_var report_verbosity, port_g, login, pass;
global_var	info_t, sock_g, sep, c;

INFO_LOCAL  = 1; 
INFO_SSH    = 2; 
INFO_RSH    = 3; 
INFO_REXEC  = 4; 
INFO_RLOGIN = 5; 
INFO_TELNET = 6;



function telnet_open_cnx(port, login, pass)
{
 local_var	s, res;
 local_var	ps;

 if ( ! get_port_state(port) ) return NULL;
 s = open_sock_tcp(port);
 if (! s) return NULL;

 res = telnet_negotiate(socket: s);
 if (strlen(res) == 0)
 {
  close(s);
  return NULL;
 }
 send(socket: s, data: strcat(login, '\r\n'));
 res = recv_until(socket: s, pattern: "[pP]assword:");
 if (strlen(res) == 0)
 {
  close(s);
  return NULL;
 }
 send(socket: s, data: strcat(pass, '\r\n'));

 ps = '([$#%>] )|([a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+ +(/|(/[^/]+)+/*) *[$#%>])';

 res = recv_until(socket: s, pattern: ps);
 if (strlen(res) == 0)
 {
  close(s);
  return NULL;
 }
 send(socket: s, data: 'thisisnotaknowncommand'+rand()+'\r\n');
 res = recv_until(socket: s, pattern: ps);
#debug_print('Bad command => ', res);
 if ('thisisnotaknowncommand' >!< res)
 {
  close(s);
  return NULL;
 }
 return s;
}

function send_rexec(port, login, pass, cmd)
{
  local_var	s, buf;

  if ( ! get_port_state(port) ) return NULL;
  s = open_priv_sock_tcp(dport: port);
  if (! s) return NULL;
  send(socket: s, data: '\0');    # No separate channel for error :-(
  send(socket: s, data: strcat(login, '\0', pass, '\0', cmd, '\0'));
  buf = recv(socket: s, length: 1);  # 0 if OK?
  if ( isnull(buf) || ord(buf[0]) > 0)
  {
   close(s);
   return NULL;
  }
  buf = recv(socket: s, length: 1024*1024);
  close(s);
#debug_print('send_rexec: cmd = ', cmd, '\nbuf = \n', buf, '\n\n');
  return buf;
}

function rlogin(port, login, pass, from)
{
 local_var	s, r;

 if ( ! get_port_state(port) ) return NULL;
 s = open_priv_sock_tcp(dport: port);
 if (!s) return NULL;
 if (! from) from = 'root';
 send(socket: s, data: '\0');
 send(socket: s, data: strcat(from, '\0', login, '\0raw/38400\0'));
 r = recv(socket: s, length: 1);
 if (r != '\0') { close(s); return NULL; }
 r = recv(socket: s, length: 1024*1024);
 if (r =~ 'Password *: *$')
 {
  send(socket: s, data: pass + '\r');
  r = recv(socket: s, length: 1024*1024);
  # display("'", ord(r[0]), "' (r)\n");
  if (r =~ 'Password *: *$')
  {
   close(s);
   return NULL;
  }
 }
 return s;
}

function send_rsh(port, login, from, cmd)
{
 local_var	s, buf;

 if (! from) from = 'root';
 s = open_priv_sock_tcp(dport: port);
 if (! s) return NULL;
 send(socket: s, data: '0\0');	# No separate channel for error :-(
 send(socket: s, data: strcat(from, '\0', login, '\0', cmd, '\0'));
 buf = recv(socket: s, length: 1);  # 0 if OK?
 if (ord(buf[0]) > 0)
 {
  close(s);
  return NULL;
 }
 buf = recv(socket: s, length: 1024*1024);
 close(s);
 return buf;
}


function info_send_cmd(cmd)
{
 local_var	buf, f;

#debug_print('info_send_cmd: cmd=', cmd);

 if (info_t == INFO_LOCAL)
 {
  if (match(string: cmd, pattern: "cat *") && ">" >!< cmd)
  {
   f = substr(cmd, 4);
   if (! file_stat(f))
   {
#debug_print('info_send_cmd: ', f, ' does not exist or cannot be read\n');
    return NULL;
   }
   else
    return fread(f);
  }
  else
  {
   if ("'" >< cmd) sep = '"';
   else sep = "'";
   return pread(cmd: "/bin/sh", argv: make_list("sh", "-c", cmd));
  }
 }

 if (info_t == INFO_SSH)
 {
  return ssh_cmd(cmd: cmd, timeout: 120);
 }

 if (info_t == INFO_RSH)
 {
  return send_rsh(login: login, port: port_g, cmd:cmd);
 }
 if (info_t == INFO_REXEC)
 {
  return send_rexec(login: login, pass: pass, port: port_g, cmd:cmd);
 }

 if (info_t == INFO_TELNET)
 {
  send(socket: sock_g, data: 
  # Yes! Two spaces (or more) are necessary
    strcat('echo NESSUS  START; ', cmd, ' 2>/dev/null; echo NESSUS  END\r\n'));
  # But just one space here!
  buf = recv_until(socket: sock_g, pattern: 'NESSUS END');
#debug_print('buf=>>>\n', buf, '<<<\n');
  recv_until(socket: sock_g, pattern: '[%$#>] ');
  # Only one space here!
  buf = strstr(buf, 'NESSUS START');
#debug_print('buf=>>>\n', buf, '<<<\n');
  c = buf - 'NESSUS START'; 
  while (c[0] == '\r' || c[0] == '\n' || c[0] == ' ' || c[0] == '\t')
   c = substr(c, 1);
  c = chomp(c - 'NESSUS END');
#if (c == buf) debug_print('info_send_cmd: could not extract command output from: ', buf);
#debug_print('c=>>>\n', c, '<<<\n');
  return c;
 }

 #log_print('info_send_cmd: unhandled case info_t=', info_t, ' - cmd=', cmd, '\n');
 return NULL;
}


function set_globals()
{
 local_var opt;
 opt = get_kb_item("global_settings/report_verbosity");

 if (opt )
        {
        if ("Verbose" >< opt ) report_verbosity = 2;
        else if ("Normal" >< opt ) report_verbosity = 1;
        else if ("Quiet" >< opt ) report_verbosity = 0;
        }
} 


set_globals();

