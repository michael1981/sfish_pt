#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42424);
 script_version ("$Revision: 1.4 $");

 script_name(english: "CGI Generic SQL Injection (blind)");
 script_summary(english: "Blind SQL injection techniques");

 script_set_attribute(attribute:"synopsis", value:
"A CGI application hosted on the remote web server is potentially
prone to SQL injection attack.");
 script_set_attribute(attribute:"description", value:
"By sending specially crafted parameters to one or more CGI scripts
hosted on the remote web server, Nessus was able to get a very
different response, which suggests that it may have been able to
modify the behavior of the application and directly access the
underlying database. 

An attacker may be able to exploit this issue to bypass
authentication, read confidential data, modify the remote database, or
even take control of the remote operating system. 

Note that this script is experimental and may be prone to false
positive." );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/securityreviews/5DP0N1P76E.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securitydocs.com/library/2651" );
 script_set_attribute(attribute:"solution", value:
"Modify the affected CGI scripts so that they properly escape
arguments." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/06");
 script_end_attributes();

 # It is not dangerous, but we want it to run after the basic SQLi tests
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(432000);	# Timeout is managed by the script itself
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_names.inc");
include("torture_cgi_func.inc");

global_var	success, reports, flaw_cnt, posreply, posregex, postheaders;
global_var	abort_time, port, poison_ok, poison_ko;
global_var	do_post;

function cmp_html(h1, h2)
{
  local_var	lines1, lines2, i, n, l1, l2, n2;

  if (h1 == h2) return 0;

  lines1 = split(h1, keep: 0);
  lines2 = split(h2, keep: 0);
  n = max_index(lines1);
  if (n2 != max_index(lines2)) return 1;

  for (i = 0; i < n; i ++)
  {
    l1 = lines1[i]; l2 = lines2[i];
    if (l1 != l2)
    {
      # This debug code can produce FPs
      if (l1 =~ '^[ \t]*Page rendered in[ \t]*:[ \t].*[0-9.]+.*s' &&
      	  l2 =~ '^[ \t]*Page rendered in[ \t]*:[ \t].*[0-9.]+.*s')
	continue;
      return 1;
    }
  }
  return 0;
}

function answers_differ(r1, r2)
{
  local_var	c1, c2;

  if (isnull(r1))
    if (isnull(r2))
      return 0;
    else
      return 1;
   else
     if (isnull(r2))
       return 1;

  c1 = int(substr(r1[0], 9));
  c2 = int(substr(r2[0], 9));
  if (c1 != c2) return 1;

  return cmp_html(h1: r1[2], h2: r2[2]);
}

# Answer to the good request is the first element, 
# answers to bogus requests come next.
global_var	req_resp_l, req_len_l;

function test(meth, url, postdata, cgi)
{
  local_var	u, r1, r2, r3, i, n, len, u1, req, act, dir, v;


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
    u = my_encode(url); u1 = u;
    if (isnull(postdata))
      r1  = http_send_recv3(item: u, port:port, method: meth);
    else
      r1  = http_send_recv3(item: u, port:port, method: meth, data: postdata, add_headers: postheaders);

    if (isnull(r1)) return 0;

    for (i = 0; ! isnull(poison_ok[i]); i ++)
    {
      u = my_encode(strcat(url, poison_ok[i]));
      if (isnull(postdata))
        r2  = http_send_recv3(item: u, port:port, method: meth);
      else
        r2  = http_send_recv3(item: u, port:port, method: meth, data: postdata, add_headers: postheaders);

      if (answers_differ(r1: r1, r2: r2)) continue;

      u = my_encode(strcat(url, poison_ko[i]));
      if (isnull(postdata))
        r2  = http_send_recv3(item: u, port:port, method: meth);
      else
        r2  = http_send_recv3(item: u, port:port, method: meth, data: postdata, add_headers: postheaders);

      if (! answers_differ(r1: r1, r2: r2)) continue;
      req = http_last_sent_request();

      # Retry initial request to make sure that the page did not change 
      # so that we do not get an FP on a forum, for example.
      if (isnull(postdata))
        r3 = http_send_recv3(item: u1, port:port, method: meth);
      else
        r3  = http_send_recv3(item: u1, port:port, method: meth, data: postdata, add_headers: postheaders);
    
      if (! answers_differ(r1: r1, r2: r3))
      {
        if (report_paranoia < 1)
	{
          # Double check
	  sleep(3);
	  if (isnull(postdata))
            r3 = http_send_recv3(item: u1, port:port, method: meth);
	  else
	    r3  = http_send_recv3(item: u1, port:port, method: meth, data: postdata, add_headers: postheaders);
	}
	if (! answers_differ(r1: r1, r2: r3))
	{
          torture_cgi_remember(port: port, method: meth, request: req, url: u, response2: r1, response: r2, cgi: cgi, vul: "BS");
          return 1;
        }
      }
    }
  }
  return -1;
}

global_var	flaw_cnt;

function test1url(url)
{
  local_var	e;
  local_var	idx, len, cgi, mypostdata;
  if (unixtime() > abort_time) return 0;

  len = strlen(url);  
  for (idx = 0; idx < len; idx ++)	
    if (url[idx] == "?")
      break;

  cgi = substr(url, 0, idx - 1);
  e = test(meth: "GET", url: url, cgi: cgi);
  if (e >= 0) return e;
  if (! do_post) return -1;

  mypostdata = substr(url, idx + 1);
  e = test(meth: 'POST', url: cgi, postdata:mypostdata, cgi: cgi);
  return e;

  return -1;
}

function test_cgi_rec(url, param_l, data_ll, idx, var_idx)
{
  local_var	i, d, u, e;
  global_var	test_arg_val;

  if (isnull(param_l[idx]))
    return test1url(url: url);

  d = data_ll[idx];
  if ( (test_arg_val == "all_pairs" || test_arg_val == "some_pairs") && var_idx > 0)
  {
    d = make_list(d[0]);
  }
  else
    var_idx = idx;

  for (i = 0; ! isnull(d[i]); i ++)
  {
    if (idx > 0)
      u = strcat(url, "&", param_l[idx], '=', d[i]);
    else
      u = strcat(url, param_l[idx], '=', d[i]);
    e = test_cgi_rec(url: u, param_l: param_l, data_ll: data_ll, var_idx: var_idx, idx: idx + 1);
    if (e >= 0) return e;
  }
  return -1;
}

function test1cgi(cgi, param_l, data_ll)
{
  local_var	i, d, p, e, n;
  global_var	stop_at_first_flaw;

  n = max_index(param_l) - 1;
  for (i = 0; i <= n; i ++)
  {
    # move the poisoned parameter at the end of the list
    if (i < n)
    {
      # We just keep one argument, to avoid a combinatory explosion
      d = data_ll[i]; data_ll[i] = data_ll[n]; data_ll[n] = make_list(d[0]);
      p = param_l[i]; param_l[i] = param_l[n]; param_l[n] = p;
    }
    init_cookiejar();
    e = test_cgi_rec(url: strcat(cgi, "?"), param_l: param_l, data_ll: data_ll, var_idx: -1, idx: 0);
    # Here, restoring the lists is not needed
    if (! e) return 0;
    if (e > 0 && stop_at_first_flaw != "never") return e;
  }
  return -1;
}

##############

init_torture_cgi();

i = 0;
poison_ok[i] = "'+AND+'b'>'a";	poison_ko[i++] = "'+AND+'b'<'a";
poison_ok[i] = "+AND+1=1";	poison_ko[i++] = "+AND+1=0";
poison_ok[i] = "+AND+1=1)";	poison_ko[i++] = "+AND+1=0)";
# Will work with /simple/ SQL requests like "SELECT * FROM users WHERE id=$ID;"
poison_ok[i] = "+AND+1=1;--";	poison_ko[i++] = "+AND+1=0;--";

################

port = get_http_port(default:80, embedded: embedded);

if (! thorough_tests && stop_at_first_flaw == "port" && get_kb_item('www/'+port+'/SQLInjection')) exit(0, strcat('A SQL injection was already found on port ', port));

success = make_array();
reports = make_array();
flaw_cnt = 0;


cgi_l = get_kb_list(strcat("www/", port, "/cgis"));
foreach cgi (cgi_l)
{
  r = eregmatch(string: cgi, pattern: "^(.+) - (.*)$");
  if (isnull(r)) continue;
  cgibase = r[1];
  args_l = r[2];
  # if (cgibase =~ ".*/$") continue;

  if (! thorough_tests && stop_at_first_flaw != "never" && get_kb_item("/tmp/SI/"+port+cgibase)) continue;

  parameters = r[2];
  vrequest = strcat(cgibase,"?");
  n = 0;
  while (strlen(parameters) > 0)
  {
    d = make_list();
    r = eregmatch(string: parameters, pattern: "^([^]]+) \[([^]]*)\] (.*)$");
    if (isnull(r))
    {
      err_print("Cannot parse: ", args_l);
      break;
    }
    param[n] = r[1]; parameters = r[3];

    if (test_arg_val == "all_combinations" || test_arg_val == "all_pairs" ||
        test_arg_val == "some_combinations" || test_arg_val == "some_pairs")
    {
      d = get_kb_list(strcat("www/", port, "/cgi-params", cgibase, "/", r[1]));
      if (isnull(d))
        d = make_list(r[2]);
      else
        d = list_uniq(make_list(r[2], make_list(d)));
    }
    else
      d = make_list(r[2]);
    if (max_tested_values > 0) d = shrink_list(l: d, n: max_tested_values);
    data[n] = d; 

    if (n > 0)
      vrequest = strcat(vrequest, '&', r[1], '=', r[2]);
    else
      vrequest = strcat(vrequest, r[1], '=', r[2]);
   n ++;
  }

  r = http_send_recv3(method: 'GET', item: my_encode(vrequest), port:port);
  if (isnull(r)) break;
  if (r[0] !~  "^HTTP/1\..* (200|302) ") continue;

  if (! test1cgi(cgi: cgibase, param_l: param, data_ll: data)) break;
}

if (flaw_cnt > 0)
{
  txt = torture_cgi_build_report(port: port, url_h: success, vul: "BS");
  security_hole(port:port, extra: txt);
  if (COMMAND_LINE) display(txt, '\n');
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
