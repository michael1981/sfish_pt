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
# torture_cgi.inc
# $Revision: 1.19 $
#
include("torture_cgi_names.inc");
include("torture_cgi_func.inc");
# include("url_func.inc");

function test(port, url, cgi, meth, postdata, pattern, headers_only, vul)
{
  global_var	abort_time, timed_out, postheaders, excluded_RE;
  local_var r, k, rep, retry, act, v, dir;

  url = my_encode(url);
  if (excluded_RE && ereg(string: url, pattern: excluded_RE, icase: 1))
      return -1;

  pattern = strcat(pattern);  # Avoid dirty warnings in debug_print
  if (COMMAND_LINE) debug_print(meth, ' URL=', url, ' - pattern=', pattern, ' - port=', port, '\n');

  # This may be very slow but is necessary for some technology like ASP.NET
  dir = NULL;
  if (isnull(postdata))
    act = make_list(url);
  else
  {
    # Cleanly encoding the posted data is not necessary so far
    # postdata = urlencode(str: postdata, case: HEX_UPPERCASE);
    act = get_kb_list(strcat("www/", port, "/form-action", cgi));
    if (isnull(act))
      act = make_list(url);
    else
    {
      v = eregmatch(string: url, pattern: "^(.*/)[^/]*");
      if (! isnull(v))
        dir = v[1];
      else
      {
        err_print("Cannot extract base directory from ", url);
	dir = "/";
      }
      act = list_uniq(make_list(url, make_list(act)));
    }
  }

 foreach url (act)
 {
  if (url[0] != "/") url = strcat(dir, url);
  debug_print(level: 2, "M=", meth, " - U=", url, " - D=", postdata);
  # The web app tests are very long, this increases the risk of network glitch 
  for (retry = 1; retry <= 3; retry ++)
  {
    if (isnull(postdata))
      r = http_send_recv3(port:port, method: meth, item: url);
    else
      r = http_send_recv3(port:port, method: meth, item: url, data: postdata, add_headers: postheaders);
    if (! isnull(r)) break;
    debug_print('http_send_recv3=NULL - retry=', retry, '\n');
    sleep(retry);
  }
  if (isnull(r))
  {
    debug_print('http_send_recv3=NULL - aborting\n');
    return 0;
  }
  if (r[0] =~ "^HTTP/1\.[01] 400 ") debug_print("test(", url, ") = ", r[0]);
  if (headers_only)
  {
    rep = extract_pattern_from_resp(pattern: pattern, string:r[1]);
    if (rep)
    {
      torture_cgi_remember(port: port, vul: vul, cgi: cgi, method: meth, url: url, postdata: postdata, response: r, report: rep);
      if (vul == "XS") set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      if (vul == "SI") set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    }
 }
 else
 {
   rep = extract_pattern_from_resp(pattern:pattern, string:r[2]);
   if (rep)
   {
     torture_cgi_remember(port: port, vul: vul, cgi: cgi, method: meth, url: url, response: r, report: rep, postdata: postdata);
     return 1;
   }
 }
 }
 return -1;
}

function test1url(port, url, cgi, pattern, vul)
{
  global_var	do_post, flaws_and_patterns, url_count;
  local_var	e, head;
  local_var	idx, len, cgi, mypostdata;

  if (unixtime() > abort_time)
  {
    debug_print('Timeout! Aborted!\n');
    timed_out ++;
    return 0;
  }
  url_count ++;
  head = 0; if (vul == "HI") head = 1;

  e = test(port:port, meth: "GET", cgi: cgi, url: url, pattern: pattern, vul:vul, headers_only: head);
  if (e >= 0) return e;
  if (! do_post) return -1;

  len = strlen(url);
  for (idx = 0; idx < len; idx ++)	
    if (url[idx] == "?")
    {
      cgi = substr(url, 0, idx - 1);
      mypostdata = substr(url, idx + 1);
      e = test(port: port, meth: 'POST', cgi: cgi, url: cgi, postdata:mypostdata, pattern: pattern, vul: vul, headers_only: head);
      return e;
    }
  return -1;
}

function test_cgi_rec(port, cgi, url, param_l, data_ll, idx, poison_idx, var_idx, pattern, vul)
{
  global_var	do_post, flaws_and_patterns, test_arg_val, try_hpp;
  local_var	i, j, d, u, u1, e, fl, pat, val, head, v, filename;

  debug_print(level: 3, "test_cgi_rec: port=", port, " url=", url, " param_l=", param_l, " idx=", idx, " poison_idx=", poison_idx, " var_idx=", var_idx);

  if (isnull(param_l[idx]))	# last argument
    return test1url(port: port, cgi: cgi, url: url, vul: vul, pattern: pattern);

  d = data_ll[idx];
  if ((test_arg_val == "all_pairs" || test_arg_val == "some_pairs") && var_idx > 0)
    d = make_list(d[0]);

  debug_print(level: 3, "test_cgi_rec: d=", d);

  if (idx == poison_idx)
  {
    foreach fl(keys(flaws_and_patterns))
     for (i = 0; ! isnull(d[i]); i ++)
     {
       pat = flaws_and_patterns[fl];

       if (idx > 0) u1 = strcat(url, "&"); else u1 = url;
       if ("VALUE"  >< fl)
       {
         if (max_index(d) > 0) val = d[0];
	 else val = "foobar";
         u = strcat(u1, param_l[idx], '=', 
	   str_replace(string: fl, find:"VALUE", replace:val));
       }
       else
       {
         if (i > 0) continue;
         if ("FILENAME" >< fl)
         {
           v = eregmatch(string: cgi, pattern: "/([^/]+)$");
	   if (isnull(v))
	     filename = cgi;
  	   else
	     filename = v[1];
 	   u = strcat(u1, param_l[idx], '=', 
	   str_replace(string: fl, find:"FILENAME", replace: filename));
         }
         else
           u = strcat(u1, param_l[idx], '=', fl);
       }

       e = test_cgi_rec(port:port, cgi: cgi, url: u, param_l: param_l, data_ll: data_ll, idx: idx + 1, poison_idx: poison_idx, var_idx: var_idx, pattern: pat, vul:vul);
       if (e >= 0) return e;

       # HTTP Parameter Pollution
       if (try_hpp && max_index(d) > 0)
       {
         val = d[0];
	 # Real value first, attack after
	 u = strcat(u1, param_l[idx], '=', val, '&', param_l[idx], '=', fl);
	 e = test_cgi_rec(port:port, cgi: cgi, url: u, param_l: param_l, data_ll: data_ll, idx: idx + 1, poison_idx: poison_idx, var_idx: var_idx, pattern: pat, vul:vul);
         if (e >= 0) return e;
	 # Attack first, real value after
	 u = strcat(u1, param_l[idx], '=', fl, '&', param_l[idx], '=', val);
	 e = test_cgi_rec(port:port, cgi: cgi, url: u, param_l: param_l, data_ll: data_ll, idx: idx + 1, poison_idx: poison_idx, var_idx: var_idx, pattern: pat, vul:vul);
         if (e >= 0) return e;
       }
      }
  }
  else
    for (i = 0; ! isnull(d[i]); i ++)
    {
      if (idx > 0)
        u = strcat(url, "&", param_l[idx], '=', d[i]);
      else
        u = strcat(url, param_l[idx], '=', d[i]);
      if (var_idx < 0 && idx != poison_idx && i > 0) var_idx = idx;
      e = test_cgi_rec(port:port, cgi: cgi, url: u, param_l: param_l, data_ll: data_ll, idx: idx + 1, poison_idx: poison_idx, var_idx: var_idx, pattern: pattern, vul:vul);
      if (e >= 0) return e;
    }
  return -1;
}


function test1cgi(port, cgi, param_l, data_ll, vul)
{
  local_var	i, e;
  global_var	stop_at_first_flaw;

  debug_print("test1cgi: port=", port, " cgi=", cgi, " vul=", vul, " param_l=", param_l);

  for (i = 0; ! isnull(param_l[i]); i ++)
  {
    init_cookiejar();
    e = test_cgi_rec(port:port, cgi: cgi, url: strcat(cgi, "?"), param_l: param_l, data_ll: data_ll, idx: 0, vul:vul, poison_idx: i, var_idx: -1);
    if (! e) return 0;
    if (e > 0 && stop_at_first_flaw != "never") return e;
  }
  return -1;
}

####

function torture_cgis(port, vul, exclude_cgi)
{
  global_var	test_arg_val, do_post, success, reports, timed_out, stop_at_first_flaw, excluded_RE, flaw_cnt;
  local_var	cgis, cgi, cgi_name, r, num_args, args, d, vals_l, e, z;
  local_var	report, cnx_errors, i, max_cnx_errors;

  cgis = get_kb_list(strcat("www/", port, "/cgis"));
  if(isnull(cgis)) return NULL;
  timed_out = 0;
  flaw_cnt = 0;
  success = make_array();
  reports = make_array();
  cnx_errors = 0;
  max_cnx_errors = 32;

  # As get_kb_list may return an array with duplicated keys, we call
  # make_list() to clean it, just in case.
  cgis = make_list(cgis);

  foreach cgi (cgis)
  {
    r = eregmatch(string: cgi, pattern: "^(.+) - (.*)$");
    if (isnull(r)) continue;
    cgi_name = r[1];
    cgi = r[2]; 

    if (! isnull(exclude_cgi) && 
        ereg(string: cgi_name, pattern: exclude_cgi, icase: 1)) continue;
    if (excluded_RE && '$' >!< excluded_RE && ereg(string: cgi_name, pattern: excluded_RE, icase: 1))
      continue;

    # No need to report several XSS...
    if (stop_at_first_flaw != "never")
    {
      # XSS & persistent XSS
      if (vul == "XS" || vul == "PX")
        if (get_kb_item("/tmp/XSS/"+port+cgi_name) || 
	    get_kb_item("/tmp/XS/"+port+cgi_name) ||
	    get_kb_item("/tmp/PX/"+port+cgi_name) ) continue;
      # Local file inclusion - remote file inclusion or directory traversal are worse
      if (vul == "LI")
        if (get_kb_item("/tmp/WI/"+port+cgi_name) || 
	    get_kb_item("/tmp/DT/"+port+cgi_name)) continue;
    }
 
    num_args = 0;
    while (strlen(cgi) > 0)
    {
      r = eregmatch(string: cgi, pattern: "^([^ ]*) \[([^]]*)\] (.*)$");
      if (isnull(r))
      {
        r = eregmatch(string: cgi, pattern: "^([^\[\]]*) \[([^]]*)\] (.*)$");
        if (isnull(r))
        {
          debug_print("Cannot parse: ", cgi);
          break;
        }
      }
      args[num_args] = r[1];
      if (test_arg_val == "all_combinations" || test_arg_val == "all_pairs" ||
      	  test_arg_val == "some_combinations" || test_arg_val == "some_pairs"  )
      {
        d = get_kb_list(strcat("www/", port, '/cgi-params', cgi_name, "/", r[1]));
        if (isnull(d))
          d = make_list(r[2]);
        else
          d = list_uniq(make_list(r[2], make_list(d)));
      }
      else
        d = make_list(r[2]);
      if (max_tested_values > 0) d = shrink_list(l: d, n: max_tested_values);
      vals_l[num_args] = d;
      cgi = r[3];
      num_args ++;
    }

    e = -1;
    #### Try incomplete URIs first - this should be quicker ####
    if (max_index(args) > 1)
    {
      for (i = 0; args[i]; i ++)
      {
        z = make_list();
	z[0] = vals_l[i];
        e = test1cgi(port:port, cgi: cgi_name, param_l: make_list(args[i]), data_ll: z, vul: vul);
	z = NULL;
	if (! e)
	{
          debug_print("Server did not answer - CGI = ", cgi_name, "\n");
	  break;
	}

        if (e > 0)
        {
          if (vul == "XS") set_kb_item(name: "/tmp/XSS/"+port+cgi_name, value: TRUE);
          if (stop_at_first_flaw != "never") break;
        }
      }
    }

    if (e > 0)
      if (stop_at_first_flaw == "port") break;
      else if (stop_at_first_flaw == "CGI") continue;

   e = test1cgi(port:port, cgi: cgi_name, param_l: args, data_ll: vals_l, vul: vul);
   if (! e)
    if (++ cnx_errors > max_cnx_errors)
    {
      debug_print("Too many failures - CGI = ", cgi_name, "\n");
      break;
    }
    else
     debug_print("Server did not answer - CGI = ", cgi_name, "\n");

   if (e > 0)
   {
     if (vul == "XS") set_kb_item(name: "/tmp/XSS/"+port+cgi_name, value: TRUE);
     if (stop_at_first_flaw == "port") break;
   }
  }

  if (cnx_errors > 0)
    set_kb_item(name: "torture_CGI/errors/"+port+"/"+vul, value: cnx_errors);

  report = torture_cgi_build_report(port: port, url_h: success, vul: vul);

  if (timed_out)
    if (!report)  set_kb_item(name: "torture_CGI/timeout/"+port, value: vul);
    else set_kb_item(name: "torture_CGI/unfinished/"+port, value: vul);

  debug_print(url_count, ' URL were tested on port ', port, ' (args=', test_arg_val, ')');
  return report;
}

