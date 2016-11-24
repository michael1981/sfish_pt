# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# torture_cgi_headers.inc
# $Revision: 1.2 $
#
include("torture_cgi_names.inc");
include("torture_cgi_func.inc");

global_var	unsafe_urls, flaw_cnt, reports, port;

#######

global_var	flaw_cnt;

url_count = 0;


function test1url(url, vul)
{
  local_var	e;
  local_var	idx, len, cgi, mypostdata;
  global_var	timed_out;
  if (unixtime() > abort_time)
  {
    timed_out ++;
    return 0;
  }
  url_count ++;

  len = strlen(url);  
  for (idx = 0; idx < len; idx ++)	
    if (url[idx] == "?")
    {
      cgi = substr(url, 0, idx - 1);

      # When all_pairs and all_combinations are implemented, this request will
      # have to be move elsewhere.
      e = test(meth: "GET", url: cgi, cgi: cgi, vul: vul);
      if (e > 0 && stop_at_first_flaw != "never") return e;

      if (url != cgi)
      {
        e = test(meth: "GET", url: url, cgi: cgi);
        if (e >= 0) return e;
      }

      if (! do_post) return -1;

      mypostdata = substr(url, idx + 1);
      e = test(meth: 'POST', url: cgi, postdata:mypostdata, cgi: cgi);
      return e;
    }
  return -1;
}

##############

init_torture_cgi();

port = get_http_port(default:80, embedded: embedded);

function reload_cookie_jars()
{
  local_var	cl;
  global_var	port;

  init_cookiejar(); load_cookiejar(jar: "webmirror-"+port);
  cl = get_http_cookie_keys();
  if (isnull(cl) || max_index(cl) == 0)
  {
    debug_print("reload_cookie_jars(port=", port, "): no cookie!\n");
    return 0;
  }
  return 1;
}

function run_injection_hdr(vul, ext_l)
{
  local_var	cnx_errors, max_cnx_errors, cgi_l, cgi, r, cgi_name, args_l;
  local_var	parameters, vrequest, n, d, e, txt, ext, sqltxt, i;

  if (vul == "SC" || vul == "SH")
  {
    sqltxt = "SQL ";
    if (! thorough_tests && stop_at_first_flaw == "port" && get_kb_item('www/'+port+'/SQLInjection'))
      exit(0, strcat('A SQL injection was already found on port ', port));
  }


  unsafe_urls = make_array();
  flaw_cnt = 0;

  cnx_errors = 0; max_cnx_errors = 32;

  foreach ext (ext_l)
  {
    cgi_l = get_kb_list(strcat("www/", port, "/content/extensions/", ext));
    if (isnull(cgi_l)) continue;
    cgi_l = make_list(cgi_l);
    foreach cgi_name (cgi_l)
    {
      if (! thorough_tests && stop_at_first_flaw != "never" && get_kb_item("/tmp/SI/"+port+cgi_name)) continue;
      if (vul == "SC")
        if (! reload_cookie_jars()) break;

      r = http_send_recv3(method: 'GET', item: cgi_name, port:port);
      if (isnull(r))
      {
        if (++ cnx_errors > max_cnx_errors)
        {
          debug_print("Too many failures (", cnx_errors, ") - CGI = ", cgi_name, "\n");
          break;
        }
        else
	{
          debug_print("Server did not answer - CGI = ", cgi_name, "\n");
	  continue;
	}
      }
      if (r[0] !~  "^HTTP/1\..* (200|302) ") continue;

      e = test1url(url: cgi_name, vul: vul);
      if (e > 0 && stop_at_first_flaw == "port") break;
      if (e == 0)
      {
        if (++ cnx_errors > max_cnx_errors)
        {
  	  debug_print("Too many failures (", cnx_errors, ") - CGI = ", cgi_name, "\n");
          break;
        }
        else
          debug_print("Server did not answer - skipping CGI = ", cgi_name, "\n");
	}
     }
  }

  cgi_l = get_kb_list(strcat("www/", port, "/cgis"));
  foreach cgi (cgi_l)
  {
    r = eregmatch(string: cgi, pattern: "^(.+) - (.*)$");
    if (isnull(r)) continue;
    cgi_name = r[1];
    args_l = r[2];
    # if (cgi_name =~ ".*/$") continue;
    if (! thorough_tests && stop_at_first_flaw != "never" && get_kb_item("/tmp/SI/"+port+cgi_name)) continue;

    # NB: Settings/HTTP/test_arg_values is not used as this would create a huge
    # number of combinations for probably no real gain. This script basically
    # works in "single" mode

    parameters = r[2];
    vrequest = strcat(cgi_name,"?");
    n = 0;
    while (strlen(parameters) > 0)
    {
      d = make_list();
      r = eregmatch(string: parameters, pattern: "^([^ ]*) \[([^]]*)\] (.*)$");
      if (isnull(r))
      {
        r = eregmatch(string: parameters, pattern: "^([^\[\]]*) \[([^]]*)\] (.*)$");
        if (isnull(r))
        {
          debug_print("Cannot parse: ", parameters);
          break;
        }
      }
      parameters = r[3];
      if (n > 0)
        vrequest = strcat(vrequest, '&', r[1], '=', r[2]);
      else
        vrequest = strcat(vrequest, r[1], '=', r[2]);
      n ++;
    }

    if (vul == "SC")
      if (! reload_cookie_jars()) break;

    r = http_send_recv3(method: 'GET', item: my_encode(vrequest), port:port);
    if (isnull(r))
    {
      if (++ cnx_errors > max_cnx_errors)
      {
        debug_print("Too many failures (", cnx_errors, ") - CGI = ", cgi_name, "\n");
	break;
      }
      else
      {
        debug_print("Server did not answer - skipping CGI = ", cgi_name, "\n");
        continue; 
      }
    }
    if (r[0] !~  "^HTTP/1\..* (200|302) ") continue;

    e = test1url(url: vrequest, vul: vul);
    if (e > 0 && stop_at_first_flaw == "port") break;
    if (e == 0)
      if (++ cnx_errors > max_cnx_errors)
      {
        debug_print("Too many failures (", cnx_errors, ") - CGI = ", cgi_name, "\n");
        break;
      }
      else
       debug_print("Server did not answer - CGI = ", cgi_name, "\n");
  }

  if (cnx_errors > 0)
    set_kb_item(name: "torture_CGI/errors/"+port+"/"+vul, value: cnx_errors);

  if (flaw_cnt > 0)
  {
    txt = torture_cgi_build_report(port: port, url_h: success, vul: vul, full_req: 1);
    security_hole(port:port, extra: txt);
    if (COMMAND_LINE) display(txt, '\n');
    if (vul == "SC" || vul == "SH")
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }

  if (timed_out)
    if (! txt)
      set_kb_item(name: "torture_CGI/timeout/"+port, value: vul);
    else
      set_kb_item(name: "torture_CGI/unfinished/"+port, value: vul);
  debug_print(url_count, " URL were tested on port ", port);
}

