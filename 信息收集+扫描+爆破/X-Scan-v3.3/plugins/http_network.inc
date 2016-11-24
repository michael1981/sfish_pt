# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
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
# $Revision: 1.17 $

global_var __ka_socket, __ka_port, __ka_enabled, __ka_last_request;
global_var __http_read_timeout, __http_sent_request;

__ka_socket = NULL;
__ka_port   = 0;
__ka_enabled = -1;
__ka_last_request = "";

__http_read_timeout = NULL;

__http_sent_request = NULL;

# Copied from http_func.inc & slightly modified to update the cookie jar
# MA 2009-07-23: this function returns NULL if the headers could not be read 
# (timeout, connection reset...), not "".
function http_recv_headers3(socket)
{
 local_var buf, line, counter;
 while ( TRUE )
 {
  counter ++;
  line = recv_line(socket:socket, length:4096, timeout: __http_read_timeout);
  buf += line;
  if (line =~ '^Set-Cookie2?:') parse_setcookie_header(header: line);
  if ( line == '\r\n' ) break;
  if ( ! strlen(line) ) break;
  if ( counter > 1024 ) break;
 }
 if (isnull(buf)) debug_print('http_recv_headers3: no header?\n');
 return buf;
}

# Compatibility function
function http_recv_headers2(socket)
{
  return http_recv_headers3(socket: socket);
}

####

function http_disable_keep_alive()
{
  __ka_enabled = 0;
  if (__ka_socket > 0)
  {
    http_close_socket(__ka_socket);
    __ka_socket = NULL;
  }
}

function http_enable_keep_alive()
{
  if (! __ka_enabled) __ka_enabled = -1;
}

function http_force_keep_alive(port)
{
  if (__ka_socket > 0 && __ka_port != port)
  {
    http_close_socket(__ka_socket);
    __ka_socket = NULL;
  }
  __ka_enabled = 1;
  __ka_port = port;
}

####

function http_reopen_socket(socket, port, keepalive)
{
  if (socket)
  {
    if (socket == __ka_socket) __ka_socket = NULL;
    http_close_socket(socket);
  }
  socket = http_open_socket(port);
  if (keepalive)
  {
    __ka_socket = socket; __ka_port = port;
  }
  return socket;
}

function http_open_socket_ka(port, keepalive)
{
  if (__ka_socket && keepalive && __ka_port == port)
      return __ka_socket;
   return http_reopen_socket(socket: __ka_socket, port: port, keepalive: keepalive);
}

function http_close_socket_ka()
{
  local_var	s;
  s = _FCT_ANON_ARGS[0];
  http_close_socket(s);
  if (s == __ka_socket)
  {
    __ka_socket = NULL;
    __ka_port = NULL;
  }
}

function disable_socket_ka()
{
 local_var	s;
 s = _FCT_ANON_ARGS[0];
 if (s == __ka_socket) __ka_socket = NULL;
}

function _http_close_socket_ka_only()
{
  local_var    s;
  s = _FCT_ANON_ARGS[0];
  if (s != __ka_socket) return;
  http_close_socket(s);
  __ka_socket = NULL;
  __ka_port = NULL;
}

##### Taken from http_keepalive.inc & adapted

#
# Based on the last headers we received, we determine if we need
# to close our socket and re-open it or not
#
function http_keepalive_check_connection(headers)
{
 local_var tmp;
 tmp = egrep(pattern:"^Connection: *Close", string:headers, icase: 1);
 if(tmp)
 {
     if ( __ka_socket ) http_close_socket(__ka_socket);
     __ka_socket = http_open_socket(__ka_port);
 }
}

function enable_keepalive(port)
{
 __ka_enabled = 1;
 __ka_port    = port;
 __ka_socket  = http_open_socket(port);
}
#
# This function determines if the remote web server is
# keep-alive-enabled or not.
#
function http_keepalive_enabled(port)
{
  local_var rq, buf, soc, r, b, kb, host;
  
  kb = get_kb_item(strcat("www/", port, "/keepalive"));

  if (kb == "yes")
  {
    enable_keepalive(port: port);
    return 1;
  }
  else if (kb == "no") return(0);

  # keep-Alive is necessary for NTLM authentication, so we try to have it
  # even on a LAN.

  host = get_preference('sc.hostname.' + get_host_ip());
  if (strlen(host) == 0) host = get_host_name();

  rq = http_mk_get_req( port: port, host: host, item: "/", 
      			 version: 11);
  rq['Pragma'] = 'no-cache';
  rq['Connection'] = 'Keep-Alive';

  soc = http_open_socket(port);
  if(!soc)return -2;
  buf = http_mk_buffer_from_req(req: rq);
  send(socket:soc, data: buf);
  r = http_recv_headers3(socket: soc);
  if (isnull(r))
  {
    http_close_socket(soc);
    return -2;
  }
  b = http_recv_body(socket: soc, headers: r);
  # Apache
  if(egrep(pattern:"^Keep-Alive:.*", string:r))
  {
    http_close_socket(soc);
    replace_or_set_kb_item(name: strcat('www/', port, '/keepalive'), value:"yes");
    enable_keepalive(port:port);
    return 1;
  }
  else if ( egrep(pattern: "^Server: *Microsoft-IIS", string: r) || 
       	    egrep(pattern:"^Connection: *Keep-Alive", string:r, icase: 1))
  {
    # IIS
    if (send(socket:soc, data: buf) == strlen(buf))
    {
      r = _http_recv(socket:soc);
      http_close_socket(soc);
      if (strlen(r) > 0)
      {
	replace_or_set_kb_item(name:strcat("www/", port, "/keepalive"), value:"yes");
	enable_keepalive(port:port);
	return 1;
      }
    }
  }

 replace_or_set_kb_item(name:strcat("www/", port, "/keepalive"), value:"no");
 return 0;
}

# Internal function - Do not call it directly!
function _http_send_recv_once(port, buf, req, ka, fetch404, only_content, no_body)
{
  local_var	s, r, status_line, headers, body, ct, head;

  s = http_open_socket_ka(port: port, keepalive: ka);
  if (! s) return NULL;

  head = 0;
  if (isnull(buf))
   if (isnull(req))
   {
     err_print('_http_send_recv_once: buf and req paramaters cannot both be NULL\n');
     return NULL;
   }
   else
   {
    if (ka)
      req['Connection'] = 'Keep-Alive';
    else
      req['Connection'] = 'Close';
    if (req['$method'] == 'HEAD') head = 1;
    buf = http_mk_buffer_from_req(req: req);
   }
  else
  {
   if (! isnull(req))
   {
    err_print('_http_send_recv_once: buf and req paramaters cannot both be set. req ignored.\n');
   }
   if (match(string: buf, pattern: "HEAD *")) head = 1;
  }

  r = send(socket: s, data: buf);
  if (r > 0)
  {
    __http_sent_request = buf;
    status_line = recv_line(socket: s, length: 4096, timeout: __http_read_timeout);
  }
  else
    status_line = NULL;

  if (! status_line && ka)
  {
     s = http_reopen_socket(socket: s, port: port, keepalive: 1);
    if (! s) return NULL;
    debug_print(level: 2, '_http_send_recv_once: socket to port ', port, ' reopen\n');
    r  = send(socket: s, data: buf);
    if (r > 0)
    {
      __http_sent_request = buf;
      status_line = recv_line(socket: s, length: 4096, timeout: __http_read_timeout);
    }
    else
      status_line = NULL;  
  }
  if (! status_line)
  {
    http_close_socket_ka(s);
    return NULL;
  }
  headers = http_recv_headers3(socket: s);
  # MA 2009-07-23: we cannot do anything very smart if we get a code and no 
  # headers. The connection was probably broken. Let's return an error now.
  if (isnull(headers))
  {
    http_close_socket_ka(s);
    return NULL;
  }

  if (no_body)
  {
    if (! head) http_close_socket_ka(s);
    if ( ! isnull(headers) ) return make_list(status_line, headers);
    else return make_list(status_line);
  }
  if (only_content)	# This is mainly used by webmirror.nasl
  {
    ct = egrep(pattern: "^Content-Type:", icase: 1, string: headers);
    if (strlen(ct) > 0 && 
        ! egrep(pattern: '^Content-Type:[ \t]*' + only_content, icase: 1, string: ct))
    {
      http_close_socket_ka(s);
      return make_list(status_line, headers);
    }
  }

  if (egrep(pattern:"^Connection: *Close", string: headers, icase: 1))
  {
    ka = 0;
    disable_socket_ka(s);	# Avoid a double close
  }
  body = NULL;
  if (fetch404 || status_line !~ '^HTTP/[01]\\.[01] +404 ')
  {
    body = http_recv_body(socket: s, headers: headers);
    if (isnull(body) && status_line =~ '^HTTP/[01]\\.[01] +200 ' && "GET " >< req['$request'])
    {
      debug_print('_http_send_recv_once: ', req['$request'], ' could not download HTTP body (port=', port, ')\n');
    }
  }
  if (ka && __ka_socket && ! head && isnull(body))
   ka = 0; # Body was not read, we don't want the next request to read it.
  if (! ka) http_close_socket_ka(s);

  if (isnull(body))
    return make_list(status_line, headers);
  else
    return make_list(status_line, headers, body);
}

function http_send_recv3(port, host, method, item, data, version, add_headers, username, password, fetch404, only_content, no_body, follow_redirect, content_type)
{
  local_var	rq;
  rq = http_mk_req( port: port, host: host, method: method, item: item, 
       		    content_type: content_type,
       		    data: data, version: version, add_headers: add_headers);
  if (isnull(rq)) return NULL;
  return
   http_send_recv_req( port: port, req: rq, 
   		       username: username, password: password, 
		       fetch404: fetch404, 
		       follow_redirect: follow_redirect,
		       only_content: only_content, no_body: no_body);
}

function http_send_recv_req(port, req, username, password, fetch404, only_content, no_body, follow_redirect)
{
  local_var	ka, buf, v;
  local_var	line, w, newuri, auth, newreqline, newport, ver;

  if(__ka_enabled == -1) __ka_enabled = http_keepalive_enabled(port:port);
  if(__ka_enabled == -2) return NULL;

  if (isnull(req)) return NULL;

  ka = __ka_enabled; 
  if (ka)
  {
    req['Connection'] = 'Keep-Alive';
    if (req['$proxy']) req['Proxy-Connection'] = 'Keep-Alive';
  }

  v = _http_send_recv_once( port: port, req: req, ka: ka, fetch404: fetch404,
      			    only_content: only_content, no_body: no_body);

  # Follow redirection - this block can hardly be put into a separate function
  # as it may update the authentication credentials.
  while (v[0] =~ '^HTTP/[01]\\.[01] +30[1237] ' && follow_redirect > 0) 
  {
    follow_redirect --;
    line = egrep(string: v[1], pattern: '^Location:', icase: 1);
    # 30x without Location header cannot be processed further
    if (strlen(line) == 0) return v;
    if (v[0] =~ '^HTTP/[01]\\.[01] +303 ') req['$method'] = "GET";
    w = eregmatch(string: chomp(line), pattern: "^Location: *(.*)", icase: 1);
    newuri = w[1];
    if (newuri !~ "^https?://")
    {
      req['$uri'] = newuri; 
      newreqline = strcat(req['$method'], ' ', newuri, ver);
    }
    else
    {
      req['$uri'] = newuri;	# Informative only
      debug_print(level: 3, 'Location=', w[1], '\n');
      w = eregmatch(string: newuri, pattern: 'https?://(([^/]+)@)?([^/:]+)(:[0-9]+)?(/.*)', icase: 1);
      debug_print(level: 4, 'w=', w, '\n');
      if (isnull(w)) return v;    # Cannot parse Location, won't go further
      req['Host'] = w[3];
      ver = ' HTTP/1.1';
      if (req['$version'] == 9) ver = '';
      else if (req['$version'] == 10) ver = ' HTTP/1.0';
      if (strlen(req['$scheme']) > 0)	# This is a proxy request
      newreqline = strcat(req['$method'], ' ', newuri, ver);
      else
      {
       if (w[2]!= '')
       {
         auth = split(w[2], sep: ':', keep: 0);
         username = auth[0];
         if (auth[1] != '') password = auth[1];
       }
       if (strlen(w[4]) > 0)
       {
         newport = int(substr(w[4], 1));
         # We won't connect to the new port, this would lead to bogus reports
         if (newport != port) return v;
       }
       newreqline = strcat(req['$method'], ' ', w[5], ver);
     }
    }
    req['$request'] = newreqline;
    debug_print(level: 3, 'newreqline=', newreqline, '\n');
    v = _http_send_recv_once( port: port, req: req, ka: ka, fetch404: fetch404,
       			      only_content: only_content, no_body: no_body);
    debug_print(level: 3, 'v=', v, '\n');
  }
  # End of redirection
  if (v[0] !~ '^HTTP/[01]\\.[01] +40[17] ') return v;

  req = http_add_auth_to_req( req: req, headers: v[1], 
      			      username: username, password: password);
  if (isnull(req)) return v;

  v = _http_send_recv_once(port: port, req: req, ka: ka, fetch404: fetch404);

#  if ( v[0] =~ '^HTTP/[01]\\.[01] +40[17] ' && 
#       egrep(string: v[1], pattern: '^(WWW|Proxy)-Authenticate: NTLM'))
#  {
#    req = http_add_auth_to_req( req: req, headers: v[1], 
#      			      username: username, password: password);
#    if (isnull(req)) return v;
#    v = _http_send_recv_once(port: port, req: req, ka: ka, fetch404: fetch404);
#  }

  return v;
}

# Maybe I'll merge http_send_recv_buf with http_send_recv_req
# Note that this "compatibility function" is the only one that allow 
# duplicated headers.
function http_send_recv_buf(port, data, username, password, fetch404, only_content, no_body)
{
  local_var	ka, cnx_line, buf, v, payload_idx, headers, rq, a;

  if (isnull(data)) return NULL;

  payload_idx = stridx(data, '\r\n\r\n');
  if (payload_idx < 0)
    headers = data;
  else
  {
    headers = substr(data, 0, payload_idx + 1);
    payload_idx += 4;
  }
  cnx_line = egrep(string: headers, pattern: "^Connection *:", icase: 1);
  ka = NULL;
  if (strlen(cnx_line) > 0)
    if ("Keep-Alive" >< ka) ka = 1;
    else if ("Close" >< ka) ka = 0;

  if (isnull(ka))
  {
   if(__ka_enabled == -1) __ka_enabled = http_keepalive_enabled(port:port);
   if(__ka_enabled == -2) return NULL;
   if (__ka_enabled > 0) ka = 1; else ka =0;
  }

  if (cnx_line)
    if (ka)
      headers = strcat(headers, 'Connection: Keep-Alive\r\n');
    else
      headers = strcat(headers, 'Connection: Close\r\n');

  if (payload_idx < 0)
   buf = headers;
  else
   buf = strcat(headers, '\r\n', substr(data, payload_idx));
  v = _http_send_recv_once( port: port, buf: buf, ka: ka, fetch404: fetch404,
      			    only_content: only_content, no_body: no_body);

  if (v[0] !~ '^HTTP/[01]\\.[01] +40[17] ') return v;

  rq = http_add_auth_to_req( req: make_array(), headers: v[1], 
      			     username: username, password: password);
  if (isnull(rq)) return v;

  while (1)
  {
    a = egrep(string: headers, pattern: "^Authorization *:", icase: 1);
    if (strlen(a) > 0)
     headers -= a;
    else
    {
     a = egrep(string: headers, pattern: "^Proxy-Authorization *:", icase: 1);
     if (strlen(a) > 0)
    headers -= a;
     else
      break;
    }
  }
  if (strlen(rq["Authorization"]) > 0)
  headers = strcat(headers, 'Authorization: ', rq["Authorization"], '\r\n');  
  if (strlen(rq["Proxy-Authorization"]) > 0)
    headers = strcat(headers, 'Proxy-Authorization: ', rq["Authorization"], '\r\n');  

  if (payload_idx < 0)
   buf = headers;
  else
   buf = strcat(headers, '\r\n\r\n', substr(data, payload_idx));
  
  v = _http_send_recv_once(port: port, buf: buf, ka: ka, fetch404: fetch404);
  return v;
}

#----------------------------------------------------------------------#

# We close our socket on exit.
function on_exit()
{
  if(__ka_socket)
  {
    http_close_socket(__ka_socket);
    __ka_socket = NULL;
  }
}

if ( 0 ) on_exit();

#### From http_func.inc

# This function does not return the headers!
# So 'length' parameter does not include headers length, even if we 
# have to read them. 
# If Content-length is set, "length" only allows the function to read 
# more data, if available. i.e., it is ignored most of the time.
#

function http_recv_body(socket, headers, length)
{
  local_var	h, cl, l, min, max, x, n, to, dobrk;
  local_var    incomplete_read;

  if (isnull(headers))
  {
    h = http_recv_headers3(socket:socket);
    if (isnull(h))
      return NULL;
  }
  else
  {
    h = headers;
  }

  l = -1;
  cl = eregmatch(pattern: '(^|\r\n)Content-length:[ \t]*([0-9]+)', string: h, icase: 1);
  if(! isnull(cl)) l = int(cl[2]);
  # "l" = Content-Length or -1 now
  max = -1;
  min = -1;

  if(l < 0 && egrep(pattern:"^transfer-encoding: chunked", string:h, icase:TRUE))
  {
   local_var tmp, body;
   body = "";
 
   dobrk = 0;
   while(1)
   {
   tmp = recv_line(socket:socket, length:4096, timeout: __http_read_timeout);
   l = hex2dec(xvalue:tmp);
   if ( l + strlen(body) >= 1048576 ) 
   {
	l = 1048576 - strlen(body);
	dobrk = 1;
	debug_print("http_recv_body: read stopped after 1MB\n");
   }
   if (l > 0)
   body  = strcat(body, recv(socket:socket, length:l, min:l, timeout: __http_read_timeout));
   # "\r\n"
   recv (socket:socket, length:2, min:2);
   if (dobrk)
    _http_close_socket_ka_only(socket);
   if (l == 0 || dobrk)
   {
     return(body); # This is expected - don't put this line before the previous
   }
   }
  }
  
  if (length) max = length;
  if (l >= 0) min = int(l);
  if (l >= max || min >= max ) max = l;
  if ( max < 0)
  {
    debug_print(level: 2, "http_recv_body: bogus or no Content-length field, and no 'length' parameter set! Defaulting to 64KB\n");
    max = 65536;
    incomplete_read = 1;
  }
  if ( max > 1048576 ) { max = 1048576; incomplete_read = 1; }
  if ( min > 1048576 ) { min = 1048576; incomplete_read = 1; }
 
  debug_print(level: 3, "http_recv_body: min=", min, "; max=", max, "\n");
  if (min > 0)
  {
    x = recv(socket: socket, length: max, min: min, timeout: __http_read_timeout);
    if (strlen(x) < max) incomplete_read = 1;
  }
  else
  {
    n = recv(socket: socket, min:max, length: max, timeout: __http_read_timeout);
    x = n;
    while ( strlen(n) >= max && max != 0 )
    {
     n = recv(socket: socket, length: max, timeout: __http_read_timeout);
     x += n;
     if( strlen(x) > 1048576){
        debug_print("http_recv_body: read stopped after 1 MB!\n");
	incomplete_read = 1;
	break;
	}
    }
  }
  if (incomplete_read)
    _http_close_socket_ka_only(socket);
  return(x);
}

# This (internal) function reads everything
# Note that bodylength will be ignored if the Content-length field is set

function _http_recv(socket, code)
{
  local_var	h, b, l;
  if (code)
  {
    h = strcat(code);	# Convert to string, just in case
    repeat
    {
      l = recv_line(socket: socket, length: 2048, timeout: __http_read_timeout);
      h = h + l;
    }
    until (! l || l =~ '^[\r\n]+$'); # EOF or empty line
    if (!l) return h;
  }
  else
  {
    h = http_recv_headers3(socket:socket);
    if (isnull(h))
    {
      return(NULL);
    }
    else if ( ! ereg(pattern:"^HTTP/.* [0-9]*", string:h) ) return h;
    h = strcat(h, '\r\n');
  }
  b = http_recv_body(socket: socket, headers: h, length:0);
  return strcat(h, b);
}

# This function reads everything
# Note that bodylength will be ignored if the Content-length field is set

function http_recv3(socket, code)
{
  local_var	h, b, l;
  if (code)
  {
    repeat
    {
      l = recv_line(socket: socket, length: 2048, timeout: __http_read_timeout);
      h = h + l;
    }
    until (! l || l =~ '^[\r\n]+$'); # EOF or empty line
    if (!l) return h;
  }
  else
  {
    code = recv_line(socket: socket, length: 2048, timeout: __http_read_timeout);
    if (! code) return NULL;
    h = http_recv_headers3(socket: socket);
    if (isnull(h))
    {
      return make_list(code);
    }
    if (code !~ "^HTTP/.* [0-9]+ ") make_list(code, h);
  }
  b = http_recv_body(socket: socket, headers: h, length:0);
  if ( ! isnull(b) )
   return make_list(code, h, b);
 else
   return make_list(code, h);
}


function http_is_dead(port, retry)
{
  local_var	soc, url, req, rq, code, h, h2, b, i;
  
  if (retry <= 0) retry = 1;	# or 0?

  i = 0;
  soc = http_open_socket(port);
  while (!soc && i++ < retry)
  {
    sleep(1);	# Should we use sleep(i) ?
    soc = http_open_socket(port);
  }
  if (! soc) return 1;
  # NB: http_head does not work against SWAT & VNC (& probably others...)
  url = strcat("/", rand_str(length: 8, charset: "abcdefghijklmnopqrstuvwxyz"));
  rq = http_mk_get_req(port: port, item: url);
  req = http_mk_buffer_from_req(req: rq);
  send(socket:soc, data:req);
  for (i = 0; i <= retry; i ++)
  {
   code = recv_line(socket:soc, length: 1024, timeout: __http_read_timeout);
   if (strlen(code) > 0)
   {
    h = http_recv_headers3(socket:soc);
    # MA 2009-07-23: if we cannot read the headers, the server is not dead as 
    # it answered with a code
    if (! isnull(h))
    {
    h2 = strcat(code, h);
    b = http_recv_body(socket: soc, headers: h2);
    }
    break;
   }
   else
    sleep(1);
  }
  http_close_socket(soc);
  if (! code) return (1);
  # 500: internal server error
  # 501: not implemented = unsupported method...
  # 502: Bad gateway = upstream server sends an invalid response
  # 503: service unavailable = temporary overloading...
  # 504: gateway timeout = no timely response from upstream server
  if (ereg(pattern: "^HTTP/1\.[01] +50[234]", string: code)) return(1);
  return (0);
}

function http_set_read_timeout()
{
  local_var	to;

  to = _FCT_ANON_ARGS[0];
  if (isnull(to))
   __http_read_timeout = NULL;
  else if (to <= 0)
  {
    err_print('http_set_read_timeout: invalid timeout ', to, ' - ignored');
    return;
  }
  else
    __http_read_timeout = to;
}

function http_last_sent_request()
{
  return __http_sent_request;
}
