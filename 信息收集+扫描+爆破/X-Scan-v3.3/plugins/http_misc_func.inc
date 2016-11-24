#
# (C) Tenable Network Security, Inc.
# $Revision: 1.10 $

function get_http_banner(port)
{
  local_var soc, sb, banner, req, body;
  
  if ( get_kb_item("Services/www/" + port + "/broken") ) return NULL;
  
  if (! get_port_state(port)) return (0);
  sb = strcat("www/real_banner/", port);
  banner = get_kb_item(sb);
  if(banner) return(banner);
  
  sb = strcat("www/banner/", port);
  banner = get_kb_list(sb);
  if ( !isnull(banner) )
  {
    banner = make_list(banner);
    return banner[0];
  }

  soc = http_open_socket(port);
  if(!soc) return (NULL);
  req = http_get(item:"/", port:port);
  send(socket:soc, data:req);
  banner = http_recv_headers2(socket:soc);
  #body = http_recv_body(socket:soc, headers: banner);
  http_close_socket(soc);
  if(banner)
	replace_kb_item(name: sb, value: banner);

  return(banner);
}

# Rewritten & modified by Tenable Network Security
function get_http_port(default, embedded)
{
  local_var	port;

  port = get_kb_item("Services/www");
  if (! port) port = default;
  if (! get_port_state(port))
  {
    exit(0, strcat('Port ', port, ' is closed'));
  }
  if (! embedded && get_kb_item("Services/www/" + port + "/embedded"))
  {
    
    exit(0, strcat('Server on port ', port, ' is embedded'));
  }
  if (http_is_broken(port: port))
  {
    exit(1, strcat('Server on port ',port, ' is broken'));
  }
  return port;
}

function declare_broken_web_server(port)
{
  set_kb_item(name: "Services/www/" +port+ "/broken", value: TRUE);
  if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Services/www/" +port+ "/working", value: TRUE);
  set_kb_item(name: "Services/www/"+port+"/declared_broken_by", value: SCRIPT_NAME);
# This function shall not set  "Services/www/"+port+"/broken/reason"
}

function http_is_broken(port)
{
  local_var	starttime, endtime, delay, r, s, timeout;

  if (get_kb_item("Services/www/"+port +"/broken")) return 1;
  if (get_kb_item("Services/www/"+port+"/working")) return 0;

  timeout = get_read_timeout();
  starttime = unixtime();
  r = http_send_recv3(port: port, method: 'GET', item: '/', version: 11, no_body: 1);

  if (isnull(r))
  {
    declare_broken_web_server(port: port);
    return 1;
  }

  endtime = unixtime();
  delay = endtime - starttime;
  if (delay > 2 * timeout)
  {
   declare_broken_web_server( port: port);
   return 1;
  }

  if (r[0] =~ '^HTTP/[0-9.]+ 503 ')
  {
    declare_broken_web_server(port: port);
    return 1;
  }

  if (r[0] =~ '^HTTP/[0-9.]+ +403 ' && delay >= timeout)
  {
    declare_broken_web_server(port: port);
    return 1;
  }

  if ("HTTP" >!< r[0])
  {
    declare_broken_web_server(port: port);
    return 1;
  }

  if (port == 5000 && r[0] =~ "^HTTP/[0-9.]+ +400 ")
  {
    declare_broken_web_server(port: port);
    return 1;
  }

  if (port == 2381 && r[0] =~ "^HTTP/1\.0 ")
  {
    declare_broken_web_server(port: port);
    return 1;
  }
  set_kb_item(name: "Services/www/" +port+ "/working", value: TRUE);
  return 0;
}

#
# That's for chunk-decoding
#
function __hex_value(num)
{
   if(num == "a")return(10);
   if(num == "b")return(11);
   if(num == "c")return(12);
   if(num == "d")return(13);
   if(num == "e")return(14);
   if(num == "f")return(15);
   return(int(num));
}


function hex2dec(xvalue)
{
 local_var ret, l, i, n, m;
  
 if(!xvalue)return(0);
 xvalue = tolower(xvalue);
 if ( '\r\n' >< xvalue )
 	l = strlen(xvalue) - 2;
 else if ( '\n' >< xvalue)
	l = strlen(xvalue) - 1;
 else   l = strlen(xvalue);

 
 ret = 0;
 m = 1;
 if ( l == 0 ) return 0;
 
 # Remove the trailing spaces
 while(xvalue[l - 1]==" " && l > 0)l--;
 
 for(i=l;i>0;i--)
 {
  n = __hex_value(num:xvalue[i - 1]) * m;
  ret = ret + n;
  m = m * 16;
 }
 return int(ret);
}

function cgi_dirs()
{
 local_var kb;
 if ( get_kb_item("Settings/disable_cgi_scanning") ) return make_list();

 kb = get_kb_list("/tmp/cgibin");
 if(isnull(kb))kb = make_list("/cgi-bin", "/scripts", "");
 else kb = make_list(kb, "");
 
 return(kb); 
}

function can_host_php(port)
{
 local_var banner, sig, files;

 if ( get_kb_item("Services/www/" + port + "/embedded") ) return 0;

 banner = get_http_banner(port:port);
 if ( ! banner ) return 0;
 else 
 {
  if ( egrep(pattern:"^Server:.*IceWarp", string:banner, icase:1 ) )
    return 1;

 if ( egrep(pattern:"^Server:.*apache|thttpd|lighttpd|aolserver|pi3web|zeus|iis", string:banner, icase:1 ) )
		{
		#display(get_host_ip(), " may host PHP\n");
		return 1;
		}
 }

 files = get_kb_list("www/" + port + "/content/extensions/php*");
 if ( !isnull(files) ) {
		#display(get_host_ip(), " hosts PHP - ", files[0], "\n");
		return 1; # Hosting .php+ files
	 	}	


 sig = get_kb_item("www/hmap/" + port + "/description");
 if ( ! sig ) { 
	#display(get_host_ip(), " has no sig\n"); 
  	# If it has a banner but did not match above, then declare this is not a PHP
	# web site (dangerous, so disabled)
	#if ( egrep(pattern:"^Server:.*", string:banner) ) return 0;
	#else 
	 return 1; # Unknown web server - might be able to host a PHP website
	}

 if ( egrep(pattern:"apache|thttpd|lighttpd|aolserver|pi3web|zeus|iis", string:sig, icase:1 ) )
	{
	#display(get_host_ip(), " may be PHP site (sig)\n");
	return 1;
	}
 else {
	#display(get_host_ip(), " is definitely NOT a PHP site (sig) - ", sig, "\n");
	return 0;
	}
}

function can_host_asp(port)
{
 local_var banner, sig, files;

 if ( get_kb_item("Services/www/" + port + "/embedded") ) return 0;

 banner = get_http_banner(port:port);
 if ( ! banner ) return 0;
 else 
 {
 if ( egrep(pattern:"^Server:.*IIS", string:banner, icase:1 ) )
		{
		#display(get_host_ip(), " may host ASP\n");
		return 1;
		}
 }

 files = get_kb_list("www/" + port + "/content/extensions/asp");
 if ( !isnull(files) ) {
		#display(get_host_ip(), " hosts ASP - ", files[0], "\n");
		return 1; # Hosting .asp files
	 	}	


 sig = get_kb_item("www/hmap/" + port + "/description");
 if ( ! sig ) { 
	#display(get_host_ip(), " has no sig\n"); 
  	# Could not fingerprint it, even though we know that IIS fingerprint
        # is quite reliable 
	if ( egrep(pattern:"^Server:.*", string:banner) ) return 0;
	else 
	 return 1; # Unknown web server - might be able to host a ASP website
	}

 if ( egrep(pattern:"iis", string:sig, icase:1 ) )
	{
	#display(get_host_ip(), " may be ASP site (sig)\n");
	return 1;
	}
 else {
	#display(get_host_ip(), " is definitely NOT a ASP site (sig) - ", sig, "\n");
	return 0;
	}
}

function build_url(port, host, qs)
{
local_var	t, url, p, n;

t = get_port_transport(port);
p = "";
if (t > ENCAPS_IP)
{
 url = "https://";
 if (port != 443) p = strcat(':', port);
}
else
{
 url = "http://";
 if (port != 80) p = strcat(':', port);
}

if (strlen(host) > 0)
n = host;
else
{
n = get_host_name();
if (n =~ "^([0-9]+\.)+in-addr\.arpa$") n = get_host_ip();
}
url = strcat(url, n, p);
if (qs[0] == '/') url = strcat(url, qs);
else url = strcat(url, '/', qs);
return url;
}


function split_url(url)
{
  local_var	r, h, p, dp;

  r = eregmatch(string: url, pattern: "^(https?)://(([^:/]+)(:[^:/]*)?@)?([^:/]+)(:[0-9]+)?([?/].*)?$", icase: 1);
  if (! isnull(r))
  {
    p = tolower(r[1]);
    h["scheme"] = p;
    if (p == "http")
    {
      dp = 80; h["ssl"] = 0;
    }
    else
    {
      dp = 443; h["ssl"] = 1;
    }
    if (! isnull(r[2]))
    {
      h["user"] = r[3];
      if (! isnull(r[4])) h["password"] = substr(r[4], 1);
    }
    h["host"] = r[5];
    if (isnull(r[6]))
      h["port"] = dp;
    else
      h["port"] = int(substr(r[6], 1));
    h["page"] = r[7];
    return h;
  }
  r = eregmatch(string: url, pattern: "^mailto://([^/]+)$", icase: 1);
  if (! isnull(r))
  {
    h["scheme"] = "mailto";
    h["address"] = r[1];
    return h;
  }
  return NULL;
}

function normalize_url_path(url)
{
  local_var	old, base, qs, i, len;

  len = strlen(url);
  for (i = 0; i < len; i ++)
    if (url[i] == '?')
      break;
  if (i == 0) return url;
  if (i < len)
  {
    base = substr(url, 0, i - 1);
    qs = substr(url, i + 1);
    if (isnull(qs)) qs = "";
  }
  else
  {
    base = url;
    qs = NULL;
  }
  base = ereg_replace(string: base, pattern: "//+", replace: "/");
  base = ereg_replace(string: base, pattern: "^/(\.\./)+", replace: "/");
  repeat
  {
    old = base;
    base = ereg_replace(string: base, pattern: "/\./", replace: "/");
  }
  until (old == base);
  repeat
  {
    old = base;
    base = ereg_replace(string: base, pattern: "/([^/.][^/]*|\.[^./][^/]*)/\.\./", replace: "/");
  }
  until (old == base);
  base = ereg_replace(string: base, pattern: "/([^/.][^/]*|\.[^./][^/]*)/\.\.$", replace: "/");
  if (isnull(qs)) return base;
  return strcat(base, "?", qs);
}

function apache_module_is_installed(module, port)
{
 local_var	b, r;

 if (get_kb_item('www/'+port+'/no_apache')) return 0;
 if (get_kb_item('www/'+port+'/no_full_apache_banner')) return -1;

 b = get_kb_item('www/'+port+'/apache_banner');
 if (isnull(b))
 {
   b = get_http_banner(port: port);
   if (isnull(b)) return 0;

   b = egrep(string: b, pattern: "^Server: +(IBM_HTTP_Server|Apache|(Oracle[0-9]+iAS/[0-9.]+ )?Oracle HTTP Server)");
   if (strlen(b) == 0)
   {
     set_kb_item(name: 'www/'+port+'/no_apache', value: TRUE);
     return 0;
   }

   r = chomp(b);
   b = strstr(r, "Apache/");
   if (isnull(b))
   {
     b = strstr(r, "Apache");
     if (isnull(b))
       b = r;
   }
   set_kb_item(name: 'www/'+port+'/apache_banner', value: b);
   # Very old banner included letters, but no list of modules
   if (! ereg(string: b, pattern: '^Apache/[0-9.]+ \\(.*\\) [^ \t].*$'))
   {
     set_kb_item(name: 'www/'+port+'/no_full_apache_banner', value: TRUE);
     return -1;
   }
 }
 if (ereg(string: b, pattern: ' '+module+'[/ ]'))
   return 1;
 else
   return 0;
}

function get_squid_banner(port)
{
  local_var	r, lines, pat, v;

  if (!get_port_state(port)) return NULL;
  r = http_get_cache(item:"/", port:port);
  if (isnull(r)) return NULL;

  pat = "([Ss]quid/[0-9]+\.[^ \)]+)";
  lines = egrep(pattern: pat, string: r);
  if (! lines) return NULL;

  foreach r (split(lines, keep:FALSE))
  {
    v = eregmatch(pattern: pat, string: r);
    if (!isnull(v)) return v[1];
  }
  return NULL;
}

