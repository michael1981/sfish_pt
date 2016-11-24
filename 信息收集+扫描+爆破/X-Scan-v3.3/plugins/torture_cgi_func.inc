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
# $Revision: 1.10 $
#

global_var	do_post, test_arg_val, stop_at_first_flaw, embedded, try_hpp;
global_var	max_tested_values, abort_time;
global_var	postheaders, url_count;
global_var	excluded_RE;

function find_pattern(string, pattern, code)
{
  if (isnull(code))
  {
    code = substr(pattern, 0, 2);
    pattern = substr(pattern, 3);
  }

  if (code == "ST:")
  {
    if (pattern >< string) return 1; else return 0;
  }
  if (code == "RE:")
  {
    return egrep(string: string, pattern: pattern);
  }
  if (code == "PA:")
  {
    return match(string: string, pattern: pattern);
  }
  if (code == "PI:")
  {
    return match(string: string, pattern: pattern, icase: 1);
  }
  err_print('find_pattern: pattern ', pattern, ' does not start with proper code\n');
  return egrep(string: string, pattern: pattern);
}

function clean_string(s)
{
 local_var	l;

 s = chomp(s);
 s = ereg_replace(string: s, pattern: '^[ \t]+', replace: ''); 
 l = strlen(s);
 if (l <= 72) return s;
 return strcat(substr(s, 0, 65), " [...]");
}

function split_long_line(line)
{
  local_var	res, len, maxlen;

  res = '';
  while (1)
  {
    len = strlen(line);
    if (len <= 72) return strcat(res, line);
    res = strcat(res, substr(line, 0, 72-1), '\n');
    line = substr(line, 72);
  }
  #NOTREACHED
}

function torture_cgi_remember(port, cgi, method, url, response, response2, vul, report, postdata, request)
{
  global_var	success, reports, requests, flaw_cnt;
  local_var	k;

  debug_print(">> torture_cgi_remember(port=", port, ", cgi=", cgi, ", method=", method, ", url=", url, ", vul=", vul, ", postdata=", postdata, ", request=", request);

#  if (method == "G") method = "GET";
#  else if (method == "P") method = "POST";

  if (isnull(request)) request = http_last_sent_request();

  if (isnull(postdata))	k = url;
  else			k = strcat(url, ' [', postdata,']');

  success[method] = strcat(success[method], k, '\n');
  if (! report)
  {
    debug_print(">> torture_cgi_remember(port=", port, ", cgi=", cgi, ", method=", method, ", url=", url, ' : report is void!\n');
    report = response[2];
  }
  reports[strcat(method, "$", k)] = report;
  requests[strcat(method, "$", k)] = request;

  set_kb_item( name: strcat("www/", port, "/cgi_", vul, "/request/", flaw_cnt),
  	       value: request );
  if (isnull(response))
    err_print("torture_cgi_remember: response is NULL\n");
  else
    set_kb_item( name: strcat("www/", port, "/cgi_", vul, "/response/", flaw_cnt),
  	       value: strcat(response[0], response[1], '\r\n', response[2]) );
  if (isnull(response2))
    debug_print("torture_cgi_remember: response2 is NULL\n");
  else
    set_kb_item( name: strcat("www/", port, "/cgi_", vul, "/response2/", flaw_cnt),
    		 value: strcat(response2[0], response2[1], '\r\n', response2[2]) );

  if (vul == "XS")
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (vul == "SI" || vul == "BS" || vul == "SH" || vul == "SC")
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  set_kb_item(name: "/tmp/"+vul+"/"+port+cgi, value: TRUE);
  flaw_cnt ++;
}


function torture_cgi_build_report(port, url_h, vul, full_req)
{
  local_var	m, r, report, rep1, rep2, z, u;
  global_var	reports, requests;

  foreach m (make_list("GET", "POST"))
  {
    rep1 = '';
    r = url_h[m];
    if (strlen(r) > 0)
    {
      rep1 = strcat(rep1, '+ The following resources may be vulnerable to ', torture_cgi_name(code: vul), ' :\n\n');
      foreach u (split(r, keep: 0))
      {
        rep1 = strcat(rep1, split_long_line(line: u), '\n');
	if (full_req)
	  rep1 = strcat(rep1, '\n-------- request --------\n', requests[strcat(m, '$', u)], '------------------------\n');
	if (report_verbosity >= 1 && ! isnull(reports))
	  rep1 = strcat(rep1, '\n-------- output --------\n', reports[strcat(m, '$', u)], '------------------------\n\n');

      }

      if (m == "GET")
      {
        rep2 = '';
        foreach u (split(r, keep: 0))
        {
	  if (strlen(u) < 72)
	  {
	    z = build_url(port: port, qs: chomp(u));
	    if (strlen(z) < 80)
	      rep2 = strcat(rep2, z, '\n');
	  }
        }
	if (rep2)
          rep1 = strcat(rep1, 'Clicking directly on these URLs might expose the vulnerabilities :\n(you will probably need to check the HTML source)\n\n', rep2, '\n');
      }

      if (strlen(rep1) > 0)
      {
        report = strcat(report, '\nUsing the ', m, ' HTTP method, Nessus found that :\n\n', rep1);
      }
    }
  }
  return report;
}



function extract_pattern_from_resp(string, pattern, code)
{
  global_var	global_patterns, FP_pattern;
  local_var	lines, i, n, i1, i2, rep;

  if (pattern == "GL")
  {
    for (i = 0; global_patterns[i]; i ++)
    {
      rep = extract_pattern_from_resp(string: string, pattern: global_patterns[i]);
      if (! isnull(rep)) return rep;      
    }
    return NULL;
  }

  lines = split(string);
  n = max_index(lines);
  for (i = 0; i < n; i ++)
    if (find_pattern(string: lines[i], pattern: pattern, code: code))
    {
      if (isnull(FP_pattern) ||
      	  ! find_pattern(string: lines[i], pattern: FP_pattern, code: code))
      break;
    }
  if (i >= n) return NULL;
  rep = "";
  i1 = i - 2; i2 = i + 2;	# Change this if you want more or less context
  if (i1 < 0) i1 = 0;
  if (i2 >= n) i2 = n - 1;
  for (i = i1; i <= i2; i ++)
    rep = strcat(rep, clean_string(s: lines[i]), '\n');
  return rep;
}

function shrink_list(l, n)
{
  local_var	v, i;

  if (max_index(l) <= n) return l;
  for (i = 0; i < n; i ++)
    v[i] = l [i];
  return v;
}

# Some attacks are already encoded, other attacks relies on the fact that 
# special characters are not encoded. We have to be careful and do not call
# urlencode()
function my_encode()
{
  return str_replace(string: _FCT_ANON_ARGS[0], find: " ", replace: "%20");
}

function init_torture_cgi()
{
  local_var	t;
  global_var	do_post, test_arg_val, stop_at_first_flaw, embedded, try_hpp, max_tested_values;
  global_var	postheaders, url_count;
  global_var	excluded_RE;

  t = int(get_kb_item("Settings/HTTP/max_run_time"));
  if (t <= 0) exit(0, 'Web application tests are disabled');
  abort_time = unixtime() + t;
  url_count = 0; 
  postheaders = make_array("Content-Type", "application/x-www-form-urlencoded");

  do_post = get_kb_item("Settings/HTTP/send_post_requests");
  test_arg_val = get_kb_item("Settings/HTTP/test_arg_values");
  if (match(string: test_arg_val, pattern: "some_*"))
  {
    max_tested_values = get_kb_item("Settings/HTTP/max_tested_values");
    if (max_tested_values <= 0) max_tested_values = 3;
  }
  else
    max_tested_values = 0;
  stop_at_first_flaw = get_kb_item("Settings/HTTP/stop_at_first_flaw");
  embedded = get_kb_item("Settings/HTTP/test_embedded");
  excluded_RE = get_kb_item("Settings/HTTP/excluded_items_regex");
  try_hpp = get_kb_item("Settings/HTTP/http_parameter_pollution");
}

