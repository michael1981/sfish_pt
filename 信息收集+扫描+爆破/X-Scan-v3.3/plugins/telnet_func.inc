#TRUSTED 5be0515471ac893abdba7e6a00289458752e7f54bc4e4705c2626c8150759d67e5f28366684eda261961aa5a7246048d94867fbf74235d3f2905bd076947d95fe83bf4e23758e8e51bfc5eaa2dacc131a691c664fd823262b8b54fa5c12c5e46af9b7b455f7ea621d1a98d3cdbe555b78c7183a51f77e77b1f5b506c5d51620cd1d5d286671d2418f5114e5480cb9c09caa6bcba064cca15f98d5d77bf450c32827b9cf875127fd13593a408a1bb2483e79b77bda05c10e4eb30abdd256abcdbb875965705d086e41d37324ae6e591a047000cb5553384a06a87818a76a4745bec98d9ca29952ace8fd38d48a198cef584524e71f4711d00159f6a6ac2064e12b9c48f0248a8e49671081b38edb7be108344c1eb849139bce159f54e37bc787f6de0031f56268b4a07a42033835d4b7a26b5d3fe0c9a67b495087e2bf972041084882e2fb39a5f803721087761eba3697275bd97739173fc51ed0861216cfb2ca44d9db20b9bbe0e46c8bdfbf7141972fabb4487e44bcd9567be90ee6d5d65dff24146ea8b35ce01f41edc86f4ed23fcb47e957b79ba23e7978da7d2c6a1e5079742ca8216ec31258df07f92b52d95c1ee616ea111a2ce6eb61f53eba4d38933218af8e2a41ca9b4b8823ee0a2eb831d1112d38602d492b41cf09e44a9fb3c264f5fa1b983a9010a79366e686bacd09c8533593b42226e56515275cfa323b189
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#

OPT_WILL 	= 0xfb;
OPT_WONT 	= 0xfc;
OPT_DO   	= 0xfd;
OPT_DONT 	= 0xfe;

OPT_SUBOPT 	= 0xfa;
OPT_ENDSUBOPT 	= 0xf0;

function get_telnet_banner(port)
{
  local_var sb, banner, soc;
  sb = string("Services/telnet/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return(banner);

  soc = open_sock_tcp(port);
  if(!soc) return (0);
  banner = telnet_negotiate(socket:soc);
  close(soc);
  if(strlen(banner)){
	if ( defined_func("replace_kb_item") )
		replace_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
	else
		set_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
	}
  return(banner);
}


function telnet_negotiate(socket, pattern)
{
 local_var opt, code, s, counter, counter2, buf, prev, timeout;

 counter = 0;
 timeout = 5;

 while ( TRUE )
 {
  s   = recv(socket:socket, length:1, timeout:timeout);
  if ( !strlen(s) ) break;
  if ( ord(s[0]) != 0xff) {
	 buf += s;
         if ( pattern && egrep(pattern:pattern, string:buf) ) break;
	 }
  else {
   counter ++;
   s  = recv(socket:socket, length:2);

   if ( ord(s[0]) == OPT_DO ) send(socket:socket,data:raw_string(0xff, OPT_WONT) + s[1]);
   else if ( ord(s[0]) == OPT_WILL ) send(socket:socket,data:raw_string(0xff, OPT_DONT) + s[1]);
   else if ( ord(s[0]) == OPT_SUBOPT )
	{
	 # The remote telnet server is autistic :/
	 prev = recv(socket:socket, length:1);
         counter2 = 0;
	 while ( ord(prev) != 0xff && ord(s[0]) != OPT_ENDSUBOPT )
	   {
	    prev = s;
 	    # No timeout - the answer is supposed to be cached
	    s    = recv(socket:socket, length:1, timeout:0);
	    if ( ! strlen(s) ) return buf;
	    counter2++;
	    if ( counter2 >= 100 ) return buf;
	   }
	}
  
   # Not necessary and may introduce endless loops
   #if ( ord(s[0]) == OPT_DONT ) send(socket:socket,data:raw_string(0xff, OPT_WONT) + s[1]);
   #if ( ord(s[0]) == OPT_WONT ) send(socket:socket,data:raw_string(0xff, OPT_DONT) + s[1]);
  }
  if ( counter >= 100 || strlen(buf) >= 4096 ) break;
 }

 
 return buf;
}

function set_telnet_banner(port, banner)
{
  local_var sb;
  sb = string("Services/telnet/banner/", port);
  if ( defined_func("replace_kb_item") )
	replace_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
  else
	set_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
}


# (C) Tenable Security

function recv_until(socket, pattern)
{
 local_var r, i, l, buf;
 i = 0; l = 0;

#debug_print('recv_until(pattern=', pattern, ')\n');
 while ( TRUE )
 {
  i ++;
  if ( i > 1024*1024 ) return NULL;
  r = recv(socket:socket, length:1);
  if ( strlen(r) == 0 ) break;
  if (r == '\0') continue;	# The shell sometimes sends back very dirty things
  l ++;
  buf += r;
  # Regex size is limited?
  if (l <= 256)
  {
   if ( egrep(pattern:pattern,string:buf) ) return buf;
  }
  else
  {
   if (egrep(pattern:pattern,string:substr(buf, l - 256))) return buf;
  }
 }
#dump(ddata: buf, dtitle: 'telnet');
#debug_print('recv_until(pattern=', pattern, ') = NULL !\n');
#dump(dtitle: 'telnet', ddata: buf);
 return NULL;
}
