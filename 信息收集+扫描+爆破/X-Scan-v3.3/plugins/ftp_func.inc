# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
#
# $Revision: 1.45 $

function ftp_close(socket)
{
  send(socket:socket, data:'QUIT\r\n');
  close(socket);
}

function get_ftp_banner(port)
{
 local_var lines, sb, banner, soc, str;
 
 lines = 0;
  sb = string("ftp/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return(banner);
  if ( get_kb_item("ftp/" + port + "/broken") ) return NULL;

  if (! get_port_state(port)) return (0);
  soc = open_sock_tcp(port);
  if(!soc) {
	set_kb_item(name:"ftp/" + port + "/broken", value:TRUE);
	return NULL;
	}
  banner = ftp_recv_line(socket:soc);
  ftp_close(socket: soc);
  if ( ! banner ) 
  {
	set_kb_item(name:"ftp/" + port + "/broken", value:TRUE);
	return NULL;
  }
  if ( defined_func("replace_kb_item") )
	replace_kb_item(name: sb, value: banner);
 else
	set_kb_item(name: sb, value: banner);
  return(banner);
}

function ftp_send_cmd(socket, cmd)
{
 send(socket:socket, data:cmd + '\r\n');
 return ftp_recv_line(socket:socket);
}

function ftp_recv_line(socket, retry)
{
 local_var	n, r, res;

 r = recv_line(socket:socket, length:65535);
 n = 0;
 while (strlen(r) == 0 && n ++ < retry)
  r = recv_line(socket:socket, length:65535);
 if(strlen(r) < 4) 
  return(r);

 n = 0;
 res = r;
 # Some FTP servers have a broken banner on several lines with a leading space
 while ((strlen(r) > 3 && r[3] == "-") || (strlen(r) >= 3 && r[0] == ' '))
 {
  n ++;
  r = recv_line(socket:socket, length:65535);
  if(n > 255)
   return(NULL);
  res = res + r;
 }
 return(res);
}


function ftp_recv_listing(socket)
{
 local_var	n, r, buf;
 n = 0;
 r = recv_line(socket:socket, length:65535);
 buf = r;
 while(strlen(r))
 {
  n ++;
  if(n > 4096)
   return(NULL);
  r = recv_line(socket:socket, length:65535);
  buf += r; 
 }
 return buf;
}

function ftp_recv_data(socket, line)
{
 local_var buf, bytes, min;
 
 if(line != NULL )
 {
  bytes = ereg_replace(pattern:"^150.*\(([0-9]*) .*\)", string:line, replace:"\1");
 }
 
 if(!bytes){ bytes = 8192; min = 1; }
 else { min = int(bytes); bytes = int(bytes); }
 
 return recv(socket:socket, min:bytes, length:bytes);
}

#
# Logs into the remote FTP server
#
function ftp_authenticate(socket, user, pass)
{
 local_var r;
 r = ftp_recv_line(socket:socket); # Receive the banner
 send(socket:socket, data:'USER ' + user + '\r\n');
 r = ftp_recv_line(socket:socket);
 if ( r[0] != '3' && 
      r[0] != '2'  ) return 0;

 send(socket:socket, data:'PASS ' + pass + '\r\n');
 r = ftp_recv_line(socket:socket);
 if ( r[0] != '2' ) return 0;
 else return 1;
}

#
# Returns the port opened on the remote side through a 'PASV' command
#
function ftp_pasv(socket)
{
 local_var r, port, array;

 if ( TARGET_IS_IPV6 )
 {
  send(socket:socket, data:'EPSV\r\n');
   r = ftp_recv_line(socket:socket);
   if ( r[0] != '2' ) return 0;
   port = egrep(pattern:"^2.9 .*\(\|\|\|[0-9]+\|\)", string:r);
   if ( ! port ) return 0;
   array = eregmatch(pattern:"^2.9 .*\(\|\|\|([0-9]+)\|\)", string:port);
   port = int(array[1]);
 }
 else
 {
   send(socket:socket, data:'PASV\r\n');
   r = ftp_recv_line(socket:socket);
   if ( r[0] != '2' ) return 0;
   port = egrep(pattern:"^227 .* \(?[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+\)?", string:r);
   if ( ! port ) return 0;
   array = eregmatch(pattern:"^227 .* \(?[0-9]+,[0-9]+,[0-9]+,[0-9]+,([0-9]+),([0-9]+)\)?", string:port);
   if ( isnull(array) ) return 0;
   port = int(array[1]) * 256 + int(array[2]);
 }
 return port;
}

function get_ftp_port(default, broken)
{
  local_var	port;

  port = get_kb_item("Services/ftp");
  if (! port) port = default;
  if (! get_port_state(port)) exit(0, strcat('Port ', port, ' is closed'));
  if (! broken && 
      (get_kb_item('ftp/'+port+'/broken') || 
       get_kb_item('ftp/'+port+'/backdoor'))) exit(0, 'FTP server is broken');
  return port;
}
