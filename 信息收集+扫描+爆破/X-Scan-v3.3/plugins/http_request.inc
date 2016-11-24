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
# $Revision: 1.11 $

# You need to include global_settings.inc and misc_func.inc
# NTLM
# include("crypto_func.inc");

# An HTTP request is store internally as a hash.
# Each key is a header.
# Two keys are reserved for special use:
# $request => the request line, e.g. GET / HTTP/1.0
# $data    => the payload (mainly for a POST)

wdayname = make_list('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun');
monthname = make_list('', 'Jan', 'Feb', 'Mar', 'Apr', 'Jun', 'Jul', 'Aug',
	   'Sep', 'Oct', 'Nov', 'Dec');

function mkdate()
{
 local_var	t;

 t = localtime(utc: 1);
 return
  strcat(wdayname[t['wday']], ', ', 
  	t['mday'], ' ', monthname[t['mon']], ' ', t['year'], ' ', 
	t['hour'] / 10, t['hour'] % 10, ':', 
	t['min'] / 10, t['min'] % 10, ':', 
	t['sec'] / 10, t['sec'] % 10, ' GMT' );
}

function http_mk_proxy_request(scheme, method, item, host, port, username, password, data, add_headers, version, content_type)
{
  local_var	ver, v, req, h, auth, k, t, url;

  if (method == 'CONNECT')
  {
    if (isnull(port) || isnull(host))
    {
      err_print('http_mk_proxy_request: host or port should not be NULL for CONNECT request\n');
      return NULL;
    }
  }
  else
  if (isnull(method) || isnull(host) || isnull(item) || isnull(scheme))
  {
    err_print('http_mk_proxy_request: scheme, host, method or item argument should not be NULL\n');
    return NULL;
  }

  if (isnull(CookieJar_value)) init_cookiejar();	
  # TBD: handle proxy authentication?

  req = make_array();
  if (isnull(version)) version = 11;
  else
    version = int(version);
  if (version < 10 || version > 11)
  {
    err_print('http_mk_proxy_request: invalid version: ', version, '\n');
    version = 11;
  }
  h = make_array();
  h['$method'] = method; h['$scheme'] = scheme; 
  h['$port'] = port; h['$version'] = version; h['$uri'] = item;
  url = '';
  if (method == 'CONNECT')
  {
    h['$uri'] = strcat(host, ':', port);
  }
  else
  {
   url = strcat(scheme, '://');
   if (strlen(username) > 0)
   {
    url = strcat(url, username);
  h['$full-uri'] = url;
    if (strlen(password) > 0)
      url = strcat(url, ':', password);
    url = strcat(url, '@');
   }
  }
  url = strcat(url, host);
  if (port > 0)
    url = strcat(url, ':', port);
  if (method != 'CONNECT')
  {
   if (item[0] != '/')
   {
    err_print('http_mk_proxy_request: item does not start with slash: ', item);
    url = strcat(url, '/');
   }
   url = strcat(url, item);
  }
  if (version == 10) req = strcat(method, ' ', url, ' HTTP/1.0');
  else req = strcat(method, ' ', url, ' HTTP/1.1');
  h['$request'] = req;
  if (method != 'CONNECT')
  {
   if (version >= 11) h['Host'] = host;
   v = get_kb_item("http/user-agent");
   if (! v) v = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)';
   h['User-Agent'] = v;

   h['Connection'] = 'Close';
   h['Pragma'] = 'no-cache';
   h['Accept'] = 'image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*';
   h['Accept-Language'] = 'en';
   h['Accept-Charset'] = 'iso-8859-1,*,utf-8';
   h['Cookie'] = mk_cookie_header(item: item);
   if (! isnull(data))
   {
    h['$data'] = data;
    h['Content-Length'] = strlen(data);
   }
  
   if (! isnull(content_type)) h['Content-Type'] = content_type;
  
   if (isnull(add_headers) || strlen(add_headers["Date"]) == 0)
     h['Date'] = mkdate();
  }

  if (typeof(add_headers) == "array")
    foreach k (keys(add_headers))
      h[k] = add_headers[k];

  return h;

}

function http_mk_req(port, host, method, item, version, data, add_headers, content_type)
{
  local_var	ver, v, req, h, auth, k, t;

  if (isnull(port) || isnull(method) || isnull(item))
  {
    err_print('http_mk_request: port, method or item argument should not be NULL\n');
    return NULL;
  }

  if (isnull(CookieJar_value)) init_cookiejar();	
  # temporary compatibility code
  # auth = get_kb_item("/tmp/http/auth/" + port);
  # if (auth) parse_setcookie_header(header: auth - "Cookie:");

  if (isnull(req)) req = make_array();
  if (isnull(version))
  {
    v = get_kb_item('http/'+port);
    if (v == "")
      version = 11;
    else
      version = int(v);
  }
  else
    version = int(version);
  if (version < 9 || version > 11)
  {
    err_print('http_mk_request: invalid version: ', version, '\n');
    version = 11;
  }
  if (version >= 11 && isnull(host))
  {
    # SC3
    host = get_preference('sc.hostname.' + get_host_ip());
    if (strlen(host) == 0) host = get_host_name();
  }
  h = make_array();
  h['$method'] = method; h['$uri'] = item; h['$port'] = port; 
  h['$version'] = version; 
  if (version <= 9)
  {
    # Note that only GET is valid
    h['$request'] = strcat(method, ' ', item);
    h['$data'] = data;
    # We do not copy the headers
    return h;
  }
  if (version == 10) req = strcat(method, ' ', item, ' HTTP/1.0');
  else
  {
    req = strcat(method, ' ', item, ' HTTP/1.1');
    h['Host'] = host;
  }

  v = get_kb_item("http/user-agent");
  if (! v) v = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)';
  h['User-Agent'] = v;

  h['Connection'] = 'Close';
  h['Pragma'] = 'no-cache';
  h['Accept'] = 'image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*';
  h['Accept-Language'] = 'en';
  h['Accept-Charset'] = 'iso-8859-1,*,utf-8';
  h['Cookie'] = mk_cookie_header(item: item);
  h['$request'] = req;
  if (! isnull(data))
  {
    h['$data'] = data;
    h['Content-Length'] = strlen(data);
  }

  if (! isnull(content_type)) h['Content-Type'] = content_type;

  if (isnull(add_headers) || strlen(add_headers["Date"]) == 0)
    h['Date'] = mkdate();

  if (typeof(add_headers) == "array")
    foreach k (keys(add_headers))
      h[k] = add_headers[k];

  return h;
}

function http_mk_get_req(port, host, item, version, data, add_headers)
{
  return http_mk_req( method: 'GET', port: port, host: host, item: item, 
  	 	      version: version, data: data, add_headers: add_headers);
}

function http_mk_head_req(port, host, item, version, data, add_headers)
{
  return http_mk_req( method: 'HEAD', port: port, host: host, item: item, 
  	 	      version: version, data: data, add_headers: add_headers);
}

function http_mk_trace_req(port, host, item, version, data, add_headers)
{
  return http_mk_req( method: 'TRACE', port: port, host: host, item: item, 
  	 	      version: version, data: data, add_headers: add_headers);
}

function http_mk_delete_req(port, host, item, version, data, add_headers)
{
  return http_mk_req( method: 'DELETE', port: port, host: host, item: item, 
  	 	      version: version, data: data, add_headers: add_headers);
}

function http_mk_post_req(port, host, item, version, data, add_headers, content_type)
{
  if (isnull(data))
    err_print('http_mk_post_req: no data parameter\n');
  return http_mk_req( method: 'POST', port: port, host: host, item: item, 
  	 	      content_type: content_type,
  	 	      version: version, data: data, add_headers: add_headers);
}

function http_mk_put_req(port, host, item, version, data, add_headers, content_type)
{
  if (isnull(data))
    err_print('http_mk_put_req: no data parameter\n');
  return http_mk_req( method: 'PUT', port: port, host: host, item: item, 
  	 	      content_type: content_type,
  	 	      version: version, data: data, add_headers: add_headers);
}

global_var	_nonceCount;

function http_mk_buffer_from_req(req)
{
  local_var	buf, h;

  if (isnull(req))
  {
    err_print('http_mk_buffer_from_req: req parameter is not set\n');
    return NULL;
  }

  if (strlen(req['$request']) == 0)
  {
    err_print('http_mk_buffer_from_req: no request line\n');
    return NULL;
  }
  buf = strcat(req['$request'], '\r\n');
  if (! isnull(req['Host'])) buf = strcat(buf, 'Host: ', req['Host'], '\r\n');
  foreach h (keys(req))
    if (h != 'Host' && h[0] != '$' && ! isnull(req[h]))
      buf = strcat(buf, h, ': ', req[h], '\r\n');
  buf = strcat(buf, '\r\n');
  if (strlen(req['$data']) > 0) buf = strcat(buf, req['$data']);
  return buf;
}

# Needed for NTLM
#
#function ascii2utf16LE(ascii)
#{
#  local_var	i, len, r;
#
#  len = strlen(ascii);
#  r = "";
#  for (i = 0; i < len; i ++)
#    r = strcat(r, ascii[i], '\0');
#  return r;
#}
#
#function LEword(blob, pos)
#{
#  return ord(blob[pos]) | (ord(blob[pos+1]) << 8);
#}
#
#function mkLEword()
#{
# local_var l;
# l = _FCT_ANON_ARGS[0];
# return  raw_string(l & 0xff, (l >> 8) & 0xff);
#}
#
#function _rand64()
#{
# return raw_string( rand() & 0XFF, rand() & 0XFF, rand() & 0XFF, rand() & 0XFF, 
# 		    rand() & 0XFF, rand() & 0XFF, rand() & 0XFF, rand() & 0XFF);
#}

function hexnumber(n)
{
 local_var	d, s, i;

 for (i = 0; i < 8; i ++)
 {
   d = n % 16;
   # 'a' = 97 
   if (d > 10) d = raw_string(d + 87);
   s = strcat(d, s);
   n /= 16;
 }
 return s;
}

# Examples:
# WWW-Authenticate: Basic realm="11.12.13.14/directory"

global_var	WWW_auth_realm, __http_remember_realm;
global_var	_nounceCount;

function http_add_auth_to_req(req, headers, username, password)
{
  local_var	auth, v, uri, realm, proxy, authR, hnc;
  local_var	ha1, ha2, resp, method, nonce, cnonce, qop, opaque, algo;
  local_var	msg, protocol, type, msg_len, flags, hostname, domain, user16;
  local_var	lm_resp_off, nt_resp_off, dom_len, user_len, host_len, user_off;
  local_var	host_off, nt_resp, lm_resp, h;

  if (isnull(req))
  {
    err_print('http_add_auth_to_req: req parameter cannot be NULL\n');
    return NULL;
  }
  auth = egrep(pattern: "^WWW-Authenticate:", string: headers, icase: 1);
  if (! auth)
  {
    auth = egrep(pattern: "^Proxy-Authenticate: *(Basic|Digest|NTLM)", string: headers, icase: 1);
    if (auth)
      proxy = 1;
    else
    {
      debug_print('http_add_auth_to_req: Neither WWW-Authenticate nor Proxy-Authenticate in headers\n');
      return NULL;
    }
  }
  auth = chomp(auth);
  if (isnull(username))
    username = get_kb_item("http/login");
  if (isnull(password))
    password = get_kb_item("http/password");
  if (strlen(username) == 0 && strlen(password) == 0)
      return NULL;

  # Basic authentication

  v = eregmatch( string: auth, icase: 1,
      		 pattern: '^(WWW|Proxy)-Authenticate: *Basic( +realm="([^"]*)")?');
  if (! isnull(v))
  {
    realm = v[3];
    if (__http_remember_realm && ! isnull(realm))
    {
      uri = req['$uri'];
      if (strlen(uri) == 0) uri = '*';
      WWW_auth_realm[uri] = realm;
    }
    authR = strcat('Basic ', base64(str: strcat(username, ":", password)));
    if (proxy) req['Proxy-Authorization'] = authR;
    else req['Authorization'] = authR;
    return req;
  }

  # Digest authentication

  v = eregmatch( string: auth, icase: 1,
      		 pattern: '^(WWW|Proxy)-Authenticate: *Digest( +realm="([^"]*)")?');
  if (! isnull(v))
  {
    realm = v[3];
    uri = req['$uri'];    
    if (__http_remember_realm && ! isnull(realm))
    {
      if (strlen(uri) == 0) uri = '*';
      WWW_auth_realm[uri] = realm;
    }
    v = eregmatch( string: auth, icase: 1,
      		 pattern: '^(WWW|Proxy)-Authenticate: *Digest +.*, *nonce="([^"]+)"');
    if (isnull(v))
    {
      debug_print(level: 1, "Cannot extract nonce\n");
      return NULL;
  }
    nonce = v[2];

    v = eregmatch( string: auth, icase: 1,
      		 pattern: '^(WWW|Proxy)-Authenticate: *Digest +.*, *algorithm=([^,]+)');
    if (! isnull(v))
      algo = v[2];
  else
      algo = "MD5";

    ha1 = MD5(strcat(username, ':', realm, ':', password));
    if ( 'qop=' >!< auth ||		# qop unspecified
       	 ereg(string: auth, pattern: ', *qop="([^"]+,)?auth[,"]'))	# qop=auth
  {
      uri = req['$uri'];
      method = req['$method'];
      ha2 = MD5(strcat(method, ':', uri));
      qop = "auth";
    }
    else
    {
      debug_print(level: 1, "auth-int Not handled yet\n");
    return NULL;
  }
    _nonceCount ++;
#    cnonce = str_replace(string: strcat(gettimeofday(), '.', rand()), find: '.', replace: '=');
    cnonce = strcat(gettimeofday(), '.', rand());
    hnc = hexnumber(n: _nonceCount);
    ha1 = hexstr(ha1); ha2 = hexstr(ha2);
    resp = MD5(strcat(ha1, ':', nonce, ':', hnc, ':', cnonce, ':', qop, ':', ha2));
    resp = hexstr(resp);

    authR = 
      strcat('Digest username="', username, '",realm="', realm, '",nonce="', nonce, '",uri="', uri, '",qop=', qop, ',nc=', hnc, ',cnonce="', cnonce, '",algorithm=', algo, ',response="', resp, '"');
    v = eregmatch( string: auth, icase: 1,
      		 pattern: '^(WWW|Proxy)-Authenticate: *Digest +.*, *opaque="([^"]*)"');
    if (! isnull(v))
    {
      opaque = v[2];
      authR = strcat(authR, ',opaque="', opaque, '"');
    }
    if (proxy) req['Proxy-Authorization'] = authR;
    else       req['Authorization'] = authR;
  return req;
}
  # NTLM authentication
  # If keep alive is disabled, this will fail miserably
  # 1st message
#  if (ereg(string: auth, pattern: '^(WWW|Proxy)-Authenticate: *NTLM *$'))
#  {
#     authR =
#      strcat('NTLM ',
#        base64(str: strcat(
#          'NTLMSSP\x00', 
#          '\x01\x00\x00\x00',		# 1: NTLMSSP_NEGOCIATE
# Negociate NTLM2, Negociate always sign, Negociate NTLM key, Request target,
# Negociate OEM, Negociate Unicode.
#	  '\x07\x82\x08\x00',
#	   '\0\0\0\0\0\0\0\0',		# Calling workstation domain
#	   '\0\0\0\0\0\0\0\0' )));	# Calling workstation name
#    if (proxy) req['Proxy-Authorization'] = authR;
#    else req['Authorization'] = authR;
#    return req;
#  }
  # NTLM: next messages
#  v = eregmatch( string: auth, 
#      		 pattern: '^(WWW|Proxy)-Authenticate: *NTLM +([A-Za-z0-9/+=]+) *$' );
#  if (! isnull(v))
#  {
#    msg = base64_decode(str: v[2]);
#    protocol = substr(msg, 0, 7);
#    if (protocol != 'NTLMSSP\0')
#    {
#      debug_print(level: 1, 'Unknown NTLM protocol: ', protocol);
#      return NULL;
#    }
#    type = ord(substr(msg, 8, 8));
#    if (type != 2)
#    {
#      debug_print(level: 1, 'Unknown NTLM type: ', type);
#      return NULL;
#    }

    # Type = 2
    # flags = substr(msg, 12, 13);
#    msg_len = LEword(blob: msg, pos: 16);
#    flags = LEword(blob: msg, pos: 20);
#    nonce = substr(msg, 24, 31);

    # Build type 3 message
#    domain = "";
#    hostname = this_host_name();
#    user16 = username;
#    domain = ascii2utf16LE(ascii: toupper(domain)); 
#    hostname = ascii2utf16LE(ascii: hostname);
#    user16 = ascii2utf16LE(ascii: username);
#    dom_len = strlen(domain);
#    user_len = strlen(user16);
#    host_len = strlen(hostname);
#    user_off = 64 + dom_len;
#    host_off = user_off + user_len;
#    lm_resp_off = host_off + host_len;
#    nt_resp_off = lm_resp_off + 0x18;
#    msg_len = nt_resp_off + 0x18;
    # NTLM2
#    cnonce = _rand64();
#    lm_resp = strcat(cnonce, '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0');
#    h = substr(MD5(strcat(nonce, cnonce)), 0, 7);
#    nt_resp = NTLM_Response(password: ascii2utf16LE(ascii: password), challenge: h);
#    nt_resp = nt_resp[0];
 
#    msg = strcat( 'NTLMSSP\0', '\x03\x00\x00\x00',
#    	  	  '\x18\x00', '\x18\x00', mkLEword(lm_resp_off), '\0\0', 
#    	  	  '\x18\x00', '\x18\x00', mkLEword(nt_resp_off), '\0\0',
#		  mkLEword(dom_len), mkLEword(dom_len), 
#		  '\x40\x00', '\0\0',	# domain offset
#		  mkLEword(user_len), mkLEword(user_len), 
#		  mkLEword(user_off), '\0\0',
#		  mkLEword(host_len), mkLEword(host_len), 
#		  mkLEword(host_off), '\0\0',
#		  '\0\0\0\0',
#		  '\0\0\0\0',
#		  '\x05\x82\x08\x00',
#		  domain,
#		  user16,
#		  hostname,
#		  lm_resp,
#		  nt_resp );
#    authR = strcat('NTLM ', base64(str: msg));
#    if (proxy) req['Proxy-Authorization'] = authR;
#    else req['Authorization'] = authR;
#    return req;
#  }

  # Unknown authentication method?

  debug_print(level: 1, 'Unsupported HTTP authentication method: ', auth);
  return NULL;
}

function http_remember_realm(off)
{
 if (off)
 {
   __http_remember_realm = 0;
   WWW_auth_realm = NULL;
 }
 else
 {
   __http_remember_realm = 1;
   WWW_auth_realm = make_array();
 }
}
