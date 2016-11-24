#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

#
# WEBMIRROR 2.0
#
#
# Written by Renaud Deraison <deraison@nessus.org>
# includes some code by H D Moore <hdmoore@digitaldefense.net>
#
# This plugin mirrors the paths used by a website. We typically care
# to obtain the list of CGIs installed on the remote host, as well as
# the path they are installed under. 
#
# Note that this plugin does not properly check for the syntax of the
# HTML pages returned : it tries to extract as much info as it
# can. We don't care about the pages extensions either (but we do
# case about the mime types)
#
# This plugin takes a really long time to complete, so it updates
# the KB as soon as data is found (as it's likely to be killed
# by nessusd against huge sites)
#
# Features :
#
#  o Directories are added in additions to URIs (ie: if there is a link to /foo/bar/a.gif, then webmirror
#    will crawl /foo/bar/)
#  o Apache and iPlanet directory listing features are used (/foo/bar will be requested as /foo/bar?D=A and
#    /foo/bar/?PageServices)   [thanks to MaXX and/or Nicolas Fischbach for the suggestion]
#  o Content is stored by various keys in the kb, to be easily reused by other scripts
#  o Forms and URIs ending in '?.*' are recognized and a list of CGIs is made from them
#  o Keep-alive support
#
# See also :
#  o torturecgis.nasl
#  o bakfiles.nasl
#  o officefiles.nasl
#
# This is version 2.0 of the plugin - it should be WAY faster and more
# accurate (i wrote a real parser).
#


include("compat.inc");

if(description)
{
 script_id(10662);
 script_version("$Revision: 1.170 $");
 
 script_name(english:"Web mirroring");
 
 script_set_attribute(attribute:"synopsis", value:
"Nessus crawled the remote web site." );
 script_set_attribute(attribute:"description", value:
"This script makes a mirror of the remote web site(s) and extracts the
list of CGIs that are used by the remote host. 

It is suggested that you change the number of pages to mirror in the
'Options' section of the client." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_end_attributes();

 script_summary(english:"Performs a quick web mirror");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "httpver.nasl", "http_login.nasl", "DDI_Directory_Scanner.nasl", "embedded_web_server_detect.nasl", "waf_detection.nasl");
 script_require_ports("Services/www", 80);

 script_add_preference(name:"Number of pages to mirror : ",
 			type:"entry",
			value:"1000");

 script_add_preference(name: "Maximum depth : ", type: "entry", value: "6");

# Now a list of pages, seperated by colons
 script_add_preference(name:"Start page : ",
 			type:"entry",
			value:"/");

# server_privileges.php is used by old phpmyadmin (e.g. 2.6.3)
# Crawling this page with the needed credentials and  "follow dynamic pages"
# is dangerous!
 script_add_preference(name: "Excluded items regex :", type: "entry", 
 value: "/server_privileges\.php");
 script_add_preference(name:"Follow dynamic pages : ",
 			type:"checkbox",
			value:"no");

 script_timeout(86400);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( get_kb_item("Settings/disable_cgi_scanning") &&
     ! get_kb_item("Settings/enable_web_app_tests"))
{
 debug_print('Settings/disable_cgi_scanning=1 and Settings/enable_web_app_tests=0\n');
 exit(0);
}

#------------------------------------------------------------------------#

global_var start_page, max_pages, dirs, num_cgi_dirs, max_cgi_dirs, follow_dynamic_pages;
global_var follow_forms, max_depth, excluded_RE;
global_var port, URLs, URLs_hash, MAILTOs_hash, ID_WebServer, Apache, iPlanet;
global_var	URL_depth, URL_ref;
global_var CGIs, Misc, Dirs, CGI_Dirs_List, URLs_30x_hash, URLs_auth_hash, Code404;
global_var misc_report, cnt, RootPasswordProtected, coffeecup, guardian, SSL_Used;
global_var URL, page, report, foo;
global_var ClearTextPasswordForms, AutoCompletePasswordForms;

global_var	auth_nb;

MAX_URL_LEN = 1024;	# Limit URL length in case the web server is crazy

auth_nb = make_array();
URL_depth = make_array();

#-------------------------------------------------------------------#

function is_in_list(list, item)
{
 local_var i;
 foreach i ( list )
	if ( i == item ) return TRUE;
 return FALSE;
}


function add_cgi_dir(dir)
{
 local_var d, dirs, r, res;
 global_var embedded;

 if ( num_cgi_dirs >= max_cgi_dirs ) return 0;
 # if (strlen(dir) >= MAX_URL_LEN) return 0;
 if (CGI_Dirs_List[dir]++) return 0;

 r = http_send_recv3(port: port, method: 'GET', item: strcat(dir, "/non-existant-", rand()));

 if(ereg(string: r[0], pattern: "^HTTP/[0-9.]+ 404 "))
 {
  dirs = cgi_dirs();
  foreach d (dirs)
  {
  if(d == dir)return(0);
  }
 
   debug_print("Adding ", dir, " as a CGI directory (num#", num_cgi_dirs, "/", max_cgi_dirs, ")\n");
   set_kb_item(name:"/tmp/cgibin", value:dir);
   set_kb_item(name: "www/"+port+"/cgibin", value:dir);
   num_cgi_dirs ++;
 }
}


#--------------------------------------------------------------------------#

function add_30x(url)
{
 if(isnull(URLs_30x_hash[url]))
 {
  set_kb_item(name:string("www/", port, "/content/30x"), value:url);
  URLs_30x_hash[url] = 1;
 }
}


function add_auth(url, auth)
{
 local_var	v, s, realm, line, n;
 global_var	auth_nb;

 if(isnull(URLs_auth_hash[url]))
 {
  set_kb_item(name:string("www/", port, "/content/auth_required"), value:url);
  URLs_auth_hash[url] = 1;
  if(url == "/")RootPasswordProtected = 1;
 }

 foreach line (split(auth, keep: 0))
 {
   v = eregmatch( string: auth, icase: 1,
     pattern: '^WWW-Authenticate: *(Basic|Digest|NTLM|Negociate)( +realm="([^"]*)")?');
   if (! isnull(v))
   {
     s = tolower(v[1]);
     set_kb_item(name: strcat("www/", port, "/authentication_scheme"), value: v[1]);
     realm = v[2];
     if (strlen(url) == 0) url = '/';
     n = auth_nb[s];
     if (isnull(n)) n = 0;
     set_kb_item(name: strcat("www/", port, "/content/", s, "_auth/url/", n), value:url);
     if (! isnull(realm))
       set_kb_item(name: strcat("www/", port, "/content/", s, "_auth/realm/", n), value: realm);
     auth_nb[s] = n+1;
    }
  }
}

#--------------------------------------------------------------------------#

num_mailto = 0;

function add_mailto(mailto, current)
{
 if ( NASL_LEVEL < 2205 ) return;
 if ( num_mailto > 100 ) return 0;
 mailto = ereg_replace(pattern:"^mailto:([^?]*)(\?.*)?", replace:"\1", string:mailto, icase:TRUE);
 if (strlen(mailto) == 0) return;
 if ( isnull(MAILTOs_hash[mailto]) )
	{
	MAILTOs_hash[mailto] = make_list(current);
	num_mailto++;
	}
  else
	{
	 if ( is_in_list(list:MAILTOs_hash[mailto], item:current) == FALSE )
		MAILTOs_hash[mailto] = make_list(MAILTOs_hash[mailto], current);
	}
  
}

function report_mailto()
{
 local_var ret;
 local_var mailto, urls, url;

 if ( num_mailto == 0 || max_index(keys(MAILTOs_hash)) == 0 ) return NULL;
 
 ret = '\n\nThe following email addresses have been gathered :\n\n';
 foreach mailto (keys(MAILTOs_hash) )
 {
   ret += '\n- \'' + mailto + '\', referenced from :\n';
   urls = MAILTOs_hash[mailto];
   foreach url ( urls )
	{
	 ret += '   ' + url + '\n';
	}
   ret += '\n';
 }

 return ret;
}

__html_entities = make_array(
"quot",		'"',
"#34", 		'"',
"#39",		"'",
"apos",		"'",
"amp",		"&",
"#38",		"&",
"lt",		"<",
"#60",		"<",
"gt",		">",
"#62",		">"
);

function decode_html_entities(u)
{
  local_var	i, len, u2, j, c, x;

  len = strlen(u);
  u2 = "";
  for (i = 0; i < len; i ++)
  {
    if (u[i] == '%' && substr(u, i+1, i+2) =~ '[0-9A-F][0-9A-F]')
    {
      c = 0;
      for (j = i + 1; j <= i + 2; j ++)
      {
        x = ord(u[j]);
	c *= 16;
        if (x >= 48 && x <= 57) c += x - 48;
        else if (x >= 65 && x <= 70) c += x - 55;
        else if (x >= 97 && x <= 102) c += x - 87;
      }
      if (c >= 33 && c <= 126)	# Printable ASCII
        u2 += raw_string(c);
      else
        u2 += substr(u, i, i+2);
      i += 2; # Loop will add 1;
    }
    else if (u[i] != '&')
      u2 += u[i];
    else
    {
      for (j = i + 1; j < len; j ++)
        if (u[j] !~ '[a-zA-Z]')
	  break;
      if (j >= len || j == i + 1 || u[j] != ';')
      {
        u2 += '&';
      }
      else
      {
        c = __html_entities[substr(u, i+1, j-1)];
	if (isnull(c))
	  u2 += substr(u, i, j);
	else
	  u2 += c;
	i = j;	# loop will add 1
      }
    }
  }
  return u2;
}

function add_url(url, depth, referer)
{
 local_var ext, dir, len;
  
 if (depth > max_depth) return NULL;
 len = strlen(url);
 if (len > MAX_URL_LEN)
 {
   debug_print("add_url(", get_host_name(), ":", port, "): URL is too long (", len , " bytes): ", substr(url, 0, 66), " ...");
   return NULL;
 }
 if (url[0] != '/')
 {
   debug_print('URI is not absolute: ', url);
   return NULL;
 }
 
 if(isnull(URLs_hash[url]))
 {
  debug_print(level: 4, "**** ADD URL ", url, " - referer=", referer, " - depth=", depth, '\n');
  URLs = make_list(URLs, url);
  if (referer) URL_ref[url] = referer;
  URLs_hash[url] = 0;
  if (! isnull(depth)) URL_depth[url] = depth;
   
  url = ereg_replace(string:url,
  			pattern:"(.*)\?.*",
			replace:"\1");
			
			
  ext = ereg_replace(pattern:".*\.([^\.]*)$", string:url, replace:"\1");
  if(strlen(ext) && ext[0] != "/" && strlen(ext) < 5 )
  {
   set_kb_item(name:string("www/", port, "/content/extensions/", ext), value:url);
  }
  
  dir = dir(url:url);
  if(dir && !Dirs[dir])
  {
   Dirs[dir] = 1;
   if ( dir !~ "^/manual" ) # Apache
    set_kb_item(name:string("www/", port, "/content/directories"), value:dir);
   if(isnull(URLs_hash[dir]))
   {
    URLs = make_list(URLs, dir);
    if(Apache)URLs  = make_list(URLs,  string(dir, "/?D=A"));
    else if(iPlanet)URLs = make_list(URLs,  string(dir, "/?PageServices"));
    URLs_hash[dir] =  0;
   }
  }
 }
}

function cgi2hash(cgi)
{
 local_var cur_cgi, cur_arg, i, ret, len;
 
 ret = make_list();
 cur_cgi = ""; 
 len = strlen(cgi);
 for(i = 0; i < len; i ++)
 {
  if (cgi[i] == " " && i+1 < len && cgi[i+1] == "[")
  {
    cur_arg = "";
    for(i = i + 2; i < len; i ++)
    {
      if(cgi[i] == "]")
      {
        ret[cur_cgi] = cur_arg;
	cur_cgi = "";
	cur_arg = "";
	if (i + 2 >= len) return ret;
	i += 2;
	break;
      }
      else cur_arg += cgi[i];
    }
  }
  cur_cgi += cgi[i];
 } 
 return ret;
}

function hash2cgi(hash)
{
 local_var ret, h;
 
 ret = "";
 foreach h (keys(hash))
 {
  ret += string(h, " [", hash[h], "] ");
 }
 return ret;
}



function add_cgi(cgi, args, form)
{
 local_var mydir, tmp, a, new_args, common, c, l;
 
 args = string(args);

 l = strlen(cgi);
 # if (l + strlen(args) > MAX_URL_LEN) return;
 if (l > 0 && cgi[l-1] == "/" && 
 ereg(string: args, pattern: "^C=[NMSD](;O)? \[[AD]\] *$", icase: FALSE))
 {
   debug_print("++++add_cgi: Apache auto-index excluded: ", cgi, "?", args, "\n");
   return;
 }
 new_args = cgi2hash(cgi:args);
 common = make_list();
 if (form)
   set_kb_item(name: strcat("www/", port, "/form-action", cgi), value: form);
 foreach c (keys(new_args))
 {
   set_kb_item(name: strcat("www/", port, "/cgi-params", cgi, "/", c), value: new_args[c]);
   if(isnull(common[c]))common[c] = new_args[c];
  }
 if(isnull(CGIs[cgi]))
 {
  debug_print(">>> ADDING CGI ",cgi, " form=", form, " args=", args, "\n");
  CGIs[cgi] = args;
  mydir = dir(url:cgi);
  add_cgi_dir(dir:mydir);
 }
 else {
  debug_print(">>> ADD CGI ",cgi, " form=", form, " args=", args, "\n");
    tmp = cgi2hash(cgi:CGIs[cgi]);
    foreach c (keys(tmp))
    {
     common[c] = tmp[c];
    }
    
    CGIs[cgi] = hash2cgi(hash:common);
    }
}



#---------------------------------------------------------------------------#

function dir(url)
{
 return ereg_replace(pattern:"(.*)/[^/]*", string:url, replace:"\1");
}

function remove_dots(url)
{
 local_var	old, len;

 while (strlen(url) > 2 && substr(url, 0, 1) == "./") url = substr(url, 2);

 url = str_replace(string: url, find: "/./", replace: "/");
 repeat
 {
   old = url;
   len = strlen(url);
    if (len > 2 && substr(url, len - 2) == "/.") url = substr(url, 0, len -3);
 }
 until (old == url);

 repeat
 {
   old = url;
   url = ereg_replace(string: url, pattern: "([^/.]|\.[^/.])+/+\.\./+", replace: "");
 }
 until (old == url);
 return url;  
}

function remove_cgi_arguments(url)
{
 local_var idx, idx2, cgi, cgi_args, args, arg, a, b, v;
 local_var idx3;

 if (strlen(url) > MAX_URL_LEN)
 {
   debug_print("remove_cgi_arguments(", get_host_name(), ":", port, "): URL is too long: ", substr(url, 0, 63), " ...");
   return NULL;
 }

 debug_print(level: 2, "***** remove_cgi_arguments '", url, "\n");

 # Remove the trailing blanks
 url = ereg_replace(string: url, pattern: '^(.*[^ \t])[ \t]+$', replace: "\1");

 idx = stridx(url, "?");
 idx2 = stridx(url, ";");
 if ( idx2 > 0 && idx2 < idx ) idx3 = idx2;
 else idx3 = idx;

 if(idx3 < 0)
   return remove_dots(url: url);
 else 
   if(idx >= strlen(url) - 1)
 {
  cgi = remove_dots(url: substr(url, 0, strlen(url) - 2));
  add_cgi(cgi:cgi, args:"");
  return cgi;
 }
 else
 {
  if(idx3 > 0) cgi = substr(url, 0, idx3 - 1);
  else cgi = ".";	# we should not come here
  
  #
  # Avoid Apache's directories indexes
  #
  if ( strlen(cgi) > 0 && cgi[strlen(cgi) - 1] == "/" && 
	ereg(pattern:"[DMNS]=[AD]", string:substr(url, idx + 1, strlen(url) - 1))) return NULL;
  cgi_args = split(substr(url, idx + 1, strlen(url) - 1), sep:"&", keep:0);

  foreach arg (make_list(cgi_args)) 
  {
   # arg = arg - "&"; arg = arg - "amp;";
   v = eregmatch(string: arg, pattern: "([^=]+)=(.*)");
   if (! isnull(v))
  	 args = string(args, v[1] , " [", v[2], "] ");
   else
   	 args = string(args, arg, " [] ");
  }
  add_cgi(cgi:cgi, args:args);
  if ( follow_dynamic_pages )
   return url;
  else
   return cgi;
 }
}


function basename(name, level)
{
 local_var i;
 
 if(strlen(name) == 0)
  return NULL;
  
  for(i = strlen(name) - 1; i >= 0 ; i --)
  {
   if(name[i] == "/")
   {
    level --;
    if(level < 0)
    { 
     return(substr(name, 0, i));
    }
   }
 }
 
 # Level is too high, we return /
 return "/";
}


function remove_double_slash(url)
{
  local_var	idx, a, b;

  idx = stridx(url, "?");
  if (idx == 0)
    return url;
  else if (idx < 0)
  {
    a = url; b = NULL;
  }
  else
  {
    if (idx > 0)
      a = substr(url, 0, idx - 1);
    else
      a = "";
    b = substr(url, idx + 1);
  }
  a = ereg_replace(string: a, pattern: "//+", replace: "/");
  if (isnull(b)) return a;
  else
    return strcat(a, "?", b);
}

global_var	same_hosts_l;
same_hosts_l = make_array();

function _wm_same_host(h)
{
 local_var	n, i;
 n = tolower(get_host_name());
 if (n == h) return 1;
 i = get_host_ip();
 if (i == h) return 1;

 # Do not call same_host, it was broken
 return 0;
}

function wm_same_host(h)
{
 h = tolower(h);
 if (same_hosts_l[h] == 'y') return 1;
 if (same_hosts_l[h] == 'n') return 0;
 if (_wm_same_host(h: h))
 {
  same_hosts_l[h] = 'y';
  return 1;
 }
 else
 {
  same_hosts_l[h] = 'n';
  return 0;
 }
}


function canonical_url(url, current)
{
 local_var num_dots, i, location, port2, e;

 url = decode_html_entities(u: url);
 debug_print(level: 2, "***** canonical '", url, "' (current:", current, ")\n");
 
 if(strlen(url) == 0)
  return NULL;
  
 if(url[0] == "#")
  return NULL;

 i = stridx(current, "?");
 if (i == 0)
  current = "";
 else if (i > 0)
  current = substr(current, 0, i - 1);

 # Links like <a href="?arg=val">xxx</a> 
 if (url[0] == '?')
 {
    url = strcat(current, url);
 }
 
 i = stridx(url, "#");
 if (i == 0)
   url = "";
 else if (i > 0)
   url = substr(url, 0, i - 1);
 
 if(url == "./" || url == ".")
   return current;
 
 debug_print(level: 3, "**** canonical(again) ", url, "\n");
 
 if(ereg(pattern:"^[a-z]+:", string:url, icase:TRUE))
 {
  e = eregmatch(string:url, pattern:"^(https?)://([^/?]+)(:[0-9]+)?([/?].*)", icase: TRUE);
  if(! isnull(e))
  {
   if (SSL_Used && strlen(e[1]) < 5)	# HTTP
     return NULL;
   if (isnull(e[3]))
     if (strlen(e[1]) == 5)	# https
       port2 = 443;
     else
       port2 = 80;
   else
     port2 = int(substr(e[3], 1));
   location = e[2];
   debug_print(level: 4, ">> ", e[1], "://", location, ":", port2, "/", e[4]);

   if (port != port2) return NULL;
   if (! wm_same_host(h: location)) return NULL;

   return remove_cgi_arguments(url: e[4]);
  }
  else if ( ereg(pattern:"^mailto:[a-z0-9_.-]+@[a-z0-9_.-]+\.[a-z0-9.-]+", string:url, icase:TRUE) )
  {
	add_mailto(mailto:url, current:current);
  }
 }
 else
 {
   url = remove_double_slash(url: url);
   debug_print(level: 3, "***** canonical '", url, "' (after remove_double_slash)");

   if(url == "/")  return "/";

 if(url[0] == "/")
  return remove_cgi_arguments(url:url);
 else
 {
  i = 0;
  num_dots = 0;
 
  while (strlen(url) > 0 && url[0] == " ") url = substr(url, 1);
  while(substr(url, 0, 2) == "../")
  {
   num_dots ++;
   url = substr(url, 3);
   if (isnull(url)) url = "";
  }
  
  while(substr(url, 0, 1) == "./")
  {
    url = substr(url, 2);
    if (isnull(url)) url = "";
  }

  debug_print(level: 3, "***** canonical '", url, "' (after .. removal)");

  url = string(basename(name:current, level:num_dots), url);
 }

 if(url[0] != "/")
 	return remove_cgi_arguments(url:string("/", url));
 else
 	return remove_cgi_arguments(url:url);
 }
 return NULL;
}



#--------------------------------------------------------------------#

 
function extract_location(loc, depth, referer)
{
 local_var url;
 
 debug_print(level: 3, '***** extract_location ', loc, ' - depth=', depth, '\n'); 
 
 if(!loc) return NULL;
 # loc = chomp(loc);

 url = canonical_url(url:loc, current:"/"); 
 if( url )
 {
   add_url(url : url, depth:depth+1, referer: referer);
   return url;
  }

  return NULL;
}



function retr(port, page, referer, depth)
{
 local_var r, q, harray, code, resp, headers, u;
 global_var	embedded;

 if (depth >= max_depth) return NULL;

 if (page[0] != '/')
 {
   debug_print('URI is not absolute: ', page);
   return NULL;
 }

 headers = NULL;
 if (referer)
  headers = make_array("Referer", build_url(port: port, qs: referer));
 r = http_send_recv3( port: port, method: 'GET', item: page, 
     		      add_headers: headers,
		      only_content: 'text/(xml|html)');
 if (isnull(r))
 {
   debug_print("Web server is dead? port=", port, "; page=", page, "\n");
   # Do not exit at once, it would disrupt the crawler on a temporary glitch
   return NULL; # No web server
 }

 debug_print(level: 4, '*** RETR page=', page, ' - referer=', referer, ' - response=', r[0], '\n');

 # if (strlen(resp) < 12 ) return NULL;
 harray = parse_http_headers(status_line: r[0], headers: r[1]);
 code = harray['$code'];
 if(code != 200)
 {
  if(code == 401 || code == 403 )
     {
# Do not use harray['www-authenticate'], there could be several 
# WWW-Authenticate headers
      add_auth(url:page, auth: egrep(string: r[1], pattern: '^WWW-Authenticate:', icase: 1));
      return NULL;
     }
  if(code == 301 || code == 302 )
  { 
   q = harray["location"];
   add_30x(url:page);
   
   # Don't echo back what we added ourselves...
   if(!(("?PageServices" >< page || "?D=A" >< page) && ("?PageServices" >< q || "?D=A" >< q)))
   	extract_location(loc: q, depth: depth, referer: referer);
   return NULL;
  }
 }
 
 if ( ! ID_WebServer )
 {
 if ( "Apache" >< harray["server"] ) Apache ++;
 else if ( "Netscape" >< harray["server"] ) iPlanet ++;
 ID_WebServer ++;
 }
 
 
 if(harray["content-type"] && harray["content-type"] !~ "text/(xml|html)")
   return NULL;
 else 
 {
    resp = r[2];
    if (!resp) return NULL; # Broken web server ?
    debug_print(level: 4, '\n----------------\n', r[2],'\n----------------\n\n' );
    resp = str_replace(string:resp, find: '\r', replace:" ");
    resp = str_replace(string:resp, find: '\n', replace:" ");
    resp = str_replace(string:resp, find: '\t', replace:" ");
    return resp;
  }
}

#---------------------------------------------------------------------------#


function token_split(content)
{
 local_var i, j, k, str;
 local_var ret, len, num;
 
 num = 0;
 
 ret = make_list();
 len = strlen(content);
 
 for (i=0;i<len;i++)
 {
  if(((i + 3) < len) && content[i]=="<" && content[i+1]=="!" && content[i+2]=="-" && content[i+3]=="-")
  {
   j = stridx(content, "-->", i);
   if( j < 0)return(ret);
   i = j;
  }
 else  
  if(content[i]=="<")
  {
   str = "";
   i ++;
   
   while(i < len && content[i] == " ")i ++;
   
   for(j = i; j < len ; j++)
   {
    if(content[j] == '"')
    {
      k = stridx(content, '"', j + 1);
      if(k < 0){
      	return(ret); # bad page
	}
      str = str + substr(content, j, k);
      j = k;
    }
    else if(content[j] == '>')
    {        
     if(ereg(pattern:"^(a|area|frame|meta|iframe|link|img|form|/form|input|button|textarea|select|/select|applet|option|script)( .*|$)", string:str, icase:TRUE))
     	{
        num ++;
     	ret = make_list(ret, str);
        if ( num > 5000 ) return ret; # Too many items
	}
     break;
    }
    else str = str + content[j];
   }
   i = j;
  }
 }
 
 return(ret);
}



function token_parse(token)
{
 local_var ret, i, j, len, current_word, word_index, current_value, char;
 
 
 ret = make_array();
 len = strlen(token);
 current_word = "";
 word_index = 0;
 
 for( i = 0 ; i < len ; i ++)
 {
  if((token[i] == " ")||(token[i] == "="))
  {
   while(i+1 < len && token[i+1] == " ")i ++;
   if(i >= len)break;
   
   if(word_index == 0)
   {
    ret["nasl_token_type"] = tolower(current_word);
   }
   else
   {
    while(i+1 < len && token[i] == " ")i ++;
    if(token[i] != "=")
    {
    	 ret[tolower(current_word)] = NULL; 
    }
    else
    {
    	i++;
        while(i+1 < len && token[i] == " ")i ++;
	char = NULL;
	if(i >= len)break;
    	if(token[i] == '"')char = '"';
	else if(token[i] == "'")char = "'";
	
	if(!isnull(char))
 	{
	 j = stridx(token, char, i + 1);
	 if(j < 0)
	  {
          debug_print("PARSE ERROR 1\n");
	  return(ret); # Parse error
	  }
	 ret[tolower(current_word)] = substr(token, i + 1, j - 1);
	 while(j+1 < len &&  token[j+1]==" ")j++;
	 i = j;
	}
        else
        {
         j = stridx(token, ' ', i + 1);
	 if(j < 0)
	  {
	   j = strlen(token);
	  }
	 ret[tolower(current_word)] = substr(token, i, j - 1);
	 i = j;
       }
     }
   }
    current_word = "";
    word_index ++;
  }
  else {
        # Filter out non-ascii text 
  	if(i < len && ord(token[i]) < 0x7e && ord(token[i]) > 0x21 )current_word = current_word + token[i];

	# Too long token
	if ( strlen(current_word) > 64 ) return ret;
	}
 }
 
 if(!word_index)ret["nasl_token_type"] = tolower(current_word);
 return ret;
}


#-------------------------------------------------------------------------#

function parse_java(elements) 
{
    local_var archive, code, codebase;

    archive = elements["archive"];
    code = elements["code"];
    codebase = elements["codebase"];

    if (codebase) 
    {
         if (archive)
            set_kb_item(name:string("www/", port, "/java_classfile"), value:string(codebase,"/",archive));
         if (code)
             set_kb_item(name:string("www/", port, "/java_classfile"), value:string(codebase,"/",code));
    } 
    else 
    {
         if (archive)
            set_kb_item(name:string("www/", port, "/java_classfile"), value:archive);
         if (code)
            set_kb_item(name:string("www/", port, "/java_classfile"), value:code);
    }
}







function parse_javascript(elements, current, depth)
{
  local_var url, pat;
  
  debug_print(level: 15, "*** JAVASCRIPT\n");
  pat = string("window\\.open\\('([^',", raw_string(0x29), "]*)'.*\\)*");
  url = ereg_replace(pattern:pat,
  		     string:elements["onclick"],
		     replace:"\1",
		     icase:TRUE);
		
  	     
  if( url == elements["onclick"])
   return NULL;
  
  url = canonical_url(url:url, current:current); 
  if( url )
  {
   add_url(url : url, depth: depth+1, referer: current);
   return url;
  }
  
  return NULL;
}

function parse_javascript_src(elements, current)
{
  local_var	v;

  if ( isnull(elements["src"]) ) return;
  v = strcat("page: ", current, " link: ", elements["src"]);
  set_kb_item(name: strcat("www/", port, "/external_javascript"), value: v);
  
  if ( ereg(pattern:"^http://([a-z]*\.)?(uc8010|ucmal)\.com/", string:elements["src"], icase:TRUE) )
  { 
   set_kb_item(name:string("www/", port, "/infected/pages"), value: v);
  }
  else if ( ereg(pattern:"^http://([a-z*]\.)?nihaorr1\.com/", string:elements["src"], icase:TRUE) )
  {
   set_kb_item(name:string("www/", port, "/infected/pages"), value: v);
  }
}


function parse_dir_from_src(elements, current)
{
 local_var src, dir;
 
 src = elements["src"];
 if( ! src ) return NULL;
 
 src = canonical_url(url:src, current:current);
 dir = dir(url:src);
 if(dir && !Dirs[dir])
 {
  Dirs[dir] = 1;
  if ( dir !~ "/manual" ) # Apache
   set_kb_item(name:string("www/", port, "/content/directories"), value:dir);
  if(isnull(URLs_hash[dir]))
   {
    URLs = make_list(URLs, dir);
    URLs_hash[dir] =  0;
   }
  }
}


function parse_href_or_src(elements, current, depth)
{
 local_var href;
 
 debug_print(level: 4, "***** parse_href_or_src href=", elements["href"], " src=", elements["src"], '\n');
 
 href = elements["href"];
 if(!href)href = elements["src"];
 
 if(!href){
	return NULL;
	}
 
 href = canonical_url(url:href, current:current);
 if( href )
 {
  add_url(url: href, depth: depth+1, referer: current);
  return href;
 }
 return NULL;
}


function parse_refresh(elements, current, depth)
{
 local_var href, content, t, sub;
 
 content = elements["content"];
 
 if(!content)
  return NULL;
 t = strstr(content, ";");
 if( t != NULL ) content = substr(t, 1, strlen(t) - 1);
 
 content = string("a ", content);
 sub = token_parse(token:content);
 
 if(isnull(sub)) return NULL;
 
 href = sub["url"];
 if(!href)
  return NULL;
 
 href = canonical_url(url:href, current:current);
 if ( href )
 {
  add_url(url: href, depth: depth+1, referer: current);
  return href;
 }
}


function parse_form(elements, current)
{
 local_var action;
 local_var dyn;

 debug_print("parse_form: elements=", elements, " current=", current, "\n");

 dyn = follow_dynamic_pages;
 follow_dynamic_pages = FALSE; 
 action = elements["action"];
 if (action == "#" || action == "") action = current;
 action = canonical_url(url:action, current:current);
 follow_dynamic_pages = dyn;
 if ( action )
   return action;
 else 
   return NULL;
}


function pre_parse(data, src_page)
{
    local_var php_path, fp_save, data2;

    if ("Index of /" >< data)
    {
    	    if(!Misc[src_page])
	    {
	    if("?D=A" >!< src_page && "?PageServices" >!< src_page)
	    	{
             	 misc_report = misc_report + string("Directory index found at ", src_page, "\n");
	   	 Misc[src_page] = 1;
		 set_kb_item( name: 'www/'+port+'/content/directory_index',
		 	      value: src_page );
		 }
	    }
    }
    
    if ("<title>phpinfo()</title>" >< data)
    {
    	    if(!Misc[src_page])
	    {
            misc_report = misc_report + string("Extraneous phpinfo() script found at ", src_page, "\n"); 
	    Misc[src_page] = 1;
	    }
            
    }
    
    if("Fatal" >< data || "Warning" >< data)
    {
    data2 = strstr(data, "Fatal");
    if(!data2)data2 = strstr(data, "Warning");
    
    data2 = strstr(data2, "in <b>");
    if ( data2 ) 
    {
    php_path = ereg_replace(pattern:"in <b>([^<]*)</b>.*", string:data2, replace:"\1");
    if (php_path != data2)
    {
        if (!Misc[src_page])
        {
            misc_report = misc_report + string("PHP script discloses physical path at ", src_page, " (", php_path, ")\n");
	    Misc[src_page] = 1;
        }
     }
    }
   }
    
   
    data2 = strstr(data, "unescape");
    
    if(data2 && ereg(pattern:"unescape..(%([0-9]|[A-Z])*){200,}.*", string:data2))
    {
     if(!Misc[src_page])
     {
      misc_report += string(src_page, " seems to have been 'encrypted' with HTML Guardian\n");
      guardian ++;
     }
    }
    
    if("CREATED WITH THE APPLET PASSWORD WIZARD WWW.COFFEECUP.COM" >< data)
    {
     if(!Misc[src_page])
     {
      misc_report += string(src_page, " seems to contain links 'protected' by CoffeCup\n");
      coffeecup++;
     }
     
      
    }

    if("SaveResults" >< data)
    { 
    fp_save = ereg_replace(pattern:'(.*SaveResults.*U-File=)"(.*)".*"', string:data, replace:"\2");
    if (fp_save != data)
     {
        if (!Misc[src_page])
        {
            misc_report = misc_report + string("FrontPage form stores results in web root at ", src_page, " (", fp_save, ")\n");
	    Misc[src_page] = 1;
        }   
     }
   }
}



function parse_main(current, data, depth)
{
 local_var tokens, elements, cgi, form_cgis, form_rcgis, form_action, form_cgis_level, args, store_cgi;
 local_var argz, token, autocomplete1, autocomplete2;
 local_var argz2, url;
 local_var current_select, current_select_name;
 local_var form_to_visit, str, tmp, i, r;
 
 current_select = make_list();
 form_cgis = make_list();
 form_action = make_list();
 form_cgis_level = 0;
 argz = NULL;
 autocomplete1 = NULL; autocomplete2 = NULL;
 store_cgi = 0;
 tokens = token_split(content: data);
 foreach token (tokens)
 {
   elements = token_parse(token:token);
   if(!isnull(elements))
   {
    
    if(elements["onclick"])
    	parse_javascript(elements:elements, current:current, depth:depth);

    if ( elements["nasl_token_type"] == "applet")
        parse_java(elements:elements);
	
    if ( elements["nasl_token_type"] == "script" )
	parse_javascript_src(elements:elements, current:current);

    if(elements["nasl_token_type"] == "a" 	  || 
       elements["nasl_token_type"] == "link" 	  ||
       elements["nasl_token_type"] == "frame"	  ||
       elements["nasl_token_type"] == "iframe"	  ||
       elements["nasl_token_type"] == "area")
        if( parse_href_or_src(elements:elements, current:current,depth:depth) == NULL) {
           debug_print(level: 20, "ERROR - ", token, " ", elements, "\n");
	  }
    if(elements["nasl_token_type"] == "img")
    	parse_dir_from_src(elements:elements, current:current);
	
    if(elements["nasl_token_type"] == "meta")
    	parse_refresh(elements:elements, current:current,depth:depth);
			  
    if( elements["nasl_token_type"] == "form" )
    {
      form_action[form_cgis_level] = elements["action"];
      form_rcgis[form_cgis_level] = elements["action"];
      cgi = parse_form(elements:elements, current:current);
      if( cgi )
      {
       
       form_cgis[form_cgis_level] = cgi;
       store_cgi = 1;
      }
      form_cgis_level ++;
      autocomplete1 = elements["autocomplete"];
    }
    
   if( elements["nasl_token_type"] == "/form")
    {
     form_cgis_level --;
     if ( form_cgis_level < 0 ) form_cgis_level = 0; # Bug on the page
     if (strlen(argz2) > 0 )
     {
      check_for_cleartext_password(cgi:form_rcgis[form_cgis_level], args:argz2, where:current);
      check_for_autocomplete_password(cgi:form_rcgis[form_cgis_level], args:argz2, where:current, autocomplete_form: autocomplete1, autocomplete_field: autocomplete2);
     }
     if( store_cgi != 0)
     {
      add_cgi(cgi:form_cgis[form_cgis_level], args:argz, form: form_action[form_cgis_level]);
     }

     if ( follow_dynamic_pages && ! isnull(form_cgis[form_cgis_level]))
     {
     debug_print(level: 5, "** before add_url: argz=", argz);
      #tmp = split(argz, sep:' ', keep:0);
      tmp = argz;
      url = form_cgis[form_cgis_level] + "?";
      i = 0;
      while (strlen(tmp) > 0)
      {
        r = eregmatch(string: tmp, pattern: "^([^ ]*) \[([^]]*)\] (.*)$");
        if (isnull(r))
        {
          r = eregmatch(string: tmp, pattern: "^([^\[\]]*) \[([^]]*)\] (.*)$");
          if (isnull(r))
          {
            err_print("parse_main(", get_host_name(), ":", port, "): cannot parse: ", tmp);
            break;
          }
	}
	if (i) url = strcat(url, "&");
	url = strcat(url, r[1], "=", r[2]);
	tmp = r[3];
	i ++;
      }
      add_url(url:url, depth: depth+1, referer: current);
     }
     argz = "";
     argz2 = "";
     autocomplete2 = NULL;
     store_cgi = 0;
    } 
   
   if( elements["nasl_token_type"] == "input" ||
       elements["nasl_token_type"] == "textarea" )
    {
     if(elements["name"])
    	 argz += string( elements["name"], " [", elements["value"], "] ");
      if ( elements["type"] == "password" )
 	{
    	 argz2 += string( "Input name : ", elements["name"], "\n");
	 if ( elements["value"] )
	   argz2 += string("Default value :  ", elements["value"], "\n");
         if (elements["autocomplete"]) autocomplete2 = elements["autocomplete"];
	}
    }
   if ( elements["nasl_token_type"] == "select" )
    {
	current_select_name = elements["name"];
    }
   if ( elements["nasl_token_type"] == "/select" )
	{
	 i = rand() % max_index(current_select);
	 argz += string(current_select_name, " [", current_select[i], "] ");
	 current_select = make_list();
	}
   if ( elements["nasl_token_type"] == "option" )
	{
	 current_select[max_index(current_select)] = elements["value"];
	}
   }
 }
}

function check_for_cleartext_password(cgi, args, where)
{
 local_var report;
 if ( cgi =~ "^https://" ) return;
 else if ( cgi !~ "^http://" && SSL_Used != 0 ) return;

 
 report += 'Page : ' + where + '\n';
 report += 'Destination page : ' + cgi + '\n';
 report +=  args;

 ClearTextPasswordForms += report + '\n\n';
}

function check_for_autocomplete_password(cgi, args, where, autocomplete_form, autocomplete_field)
{
 local_var report;

 autocomplete_field = tolower(autocomplete_field);
 autocomplete_form = tolower(autocomplete_form);
 if ("off" >< autocomplete_field) return;
 if ("on" >!< autocomplete_field && "off" >< autocomplete_form) return;
 report = strcat('Page : ', where, '\nDestination Page : ', cgi, '\n', args, '\n\n');
 AutoCompletePasswordForms = strcat(AutoCompletePasswordForms, report, '\n\n');
}

#----------------------------------------------------------------------#
#				MAIN()				       #
#----------------------------------------------------------------------#


start_page = script_get_preference("Start page : ");
if(isnull(start_page) || start_page == "")start_page = "/";

max_pages = int(script_get_preference( "Number of pages to mirror : " ));
if(max_pages <= 0)
  if (COMMAND_LINE)
   max_pages = 9999;
  else
   max_pages = 1000;

follow_dynamic_pages = script_get_preference("Follow dynamic pages : ");
if ( follow_dynamic_pages && follow_dynamic_pages == "yes" )
    follow_dynamic_pages = TRUE; 
else
    follow_dynamic_pages = FALSE; 

num_cgi_dirs = 0;
if ( thorough_tests ) 
	max_cgi_dirs = 1024;
else 
	max_cgi_dirs = 16;

excluded_RE = script_get_preference("Excluded items regex :");
if (!isnull(excluded_RE) && strlen(excluded_RE) == 0) excluded_RE = NULL;
if (! isnull(excluded_RE))
 set_kb_item(name: "Settings/HTTP/excluded_items_regex", value: excluded_RE);

max_depth = int(script_get_preference("Maximum depth : "));
if (max_depth <= 0) max_depth = 16777216;

embedded = get_kb_item("Settings/HTTP/test_embedded");
port = get_http_port(default: 80, embedded: embedded);

if (COMMAND_LINE)	# TESTS
{
 max_pages = 1000; debug_level = 2; follow_dynamic_pages = TRUE;
}

if ( get_port_transport(port) != ENCAPS_IP )
	SSL_Used = 1;
else
	SSL_Used = 0;

URLs = split(start_page, sep: ":", keep: 0);
foreach p (URLs) URLs_hash[p] = 0;
# Imported logs from web_app_test_settings.nasl
l = get_kb_list("WebAppTests/ImportedURL");
if (! isnull(l))
{
  n = max_index(URLs);
  foreach p (make_list(l))
  {
    URLs_hash[p] = 0;
    URLs[n++] = p;
  }
}
  
dirs = get_kb_list(string("www/", port, "/content/directories"));
if(dirs) URLs = make_list(URLs, dirs);

dirs = get_kb_list(string("www/", port, "/content/directories/require_auth"));
if(dirs) URLs = make_list(URLs, dirs);

MAILTOs_hash = make_array();


ID_WebServer = 0;
Apache = 0;
iPlanet = 0;

CGIs = make_list();
Misc = make_list();
Dirs = make_list();

CGI_Dirs_List = make_list();

URLs_30x_hash = make_list();
URLs_auth_hash = make_list();


Code404 = make_list();

misc_report = "";
cnt = 0;

RootPasswordProtected = 0;

guardian  = 0;
coffeecup = 0;


pass = 0;
while (max_index(URLs) > 0)
{
  pass ++;
  debug_print(level: 1, '**** pass=', pass, ' - port=', port);
  url_l = URLs;
  url_ref_l = URL_ref;
  URLs = make_list(); URL_ref = make_list();
  foreach u (url_l)
  {
    u = remove_dots(url: u);

    if( ! URLs_hash[u] && 
        (isnull(excluded_RE) || 
        ! ereg(string: u, pattern: excluded_RE, icase: 1)) )
    {
      dpt = URL_depth[u];
      if (isnull(dpt)) dpt = pass - 1;
      debug_print(level: 2, 'URL=', u, ' - depth=', URL_depth[u], ' - pass=', pass, '\n');
      page = retr(port:port, page: u, depth: dpt, referer: url_ref_l[u]);
      if (!isnull(page))
	{
	  cnt ++;
	  pre_parse(src_page: u, data:page);
	  parse_main(data:page, current: u, depth: dpt);
 	  URLs_hash[u] = 1;
	  if(cnt >= max_pages) break;
	}
    }
  }
  if(cnt >= max_pages) break;
}


if(cnt == 1)
{
 if(RootPasswordProtected)
 {
  set_kb_item(name:string("www/", port, "/password_protected"), value:TRUE);
 }
}


#display("-----------------------------------------\n");


report = "";


foreach foo (keys(CGIs))
{
 args = CGIs[foo];
 if(!args) args = "";
 set_kb_item(name:string("www/", port, "/cgis"), value:string(foo, " - ", args));
 if ( strlen(args) > 72 ) args = substr(args, 0, 69) + "...";
  
 if(!report) 
 	report = string("The following CGI have been discovered :\n\nSyntax : cginame (arguments [default value])\n\n", foo, " (", args, ")\n");
 else
 	report = string(report, foo, " (", args, ")\n");

 if ( strlen(report) > 40000 ) break;
}

if(misc_report)
{ 

 report =  string(report, "\n\n", misc_report);
}

report += report_mailto();

if(guardian)
{
 report += string("
 
HTML Guardian is a tool which claims to encrypt web pages, whereas it simply
does a transposition of the content of the page. It is is no way a safe
way to make sure your HTML pages are protected.

See also : http://www.securityfocus.com/archive/1/315950
BID : 7169");
}


if(coffeecup)
{
 report += "
 
CoffeeCup Wizard is a tool which claims to encrypt links to web pages,
to force users to authenticate before they access the links. However,
the 'encryption' used is a simple transposition method which can be 
decoded without the need of knowing a real username and password.

BID : 6995 7023";
}



if(strlen(report))
{
 security_note(port:port, extra:'\n'+report);
 if (COMMAND_LINE) display(report);
}

if ( strlen(ClearTextPasswordForms) )
{
 set_kb_item(name:"www/" + port + "/ClearTextPasswordForms", value:ClearTextPasswordForms);
}

if ( strlen(AutoCompletePasswordForms) )
{
 set_kb_item(name:"www/" + port + "/AutoCompletePasswordForms", value:AutoCompletePasswordForms);
}

cj = strcat("webmirror-", port);
store_cookiejar(cj);
