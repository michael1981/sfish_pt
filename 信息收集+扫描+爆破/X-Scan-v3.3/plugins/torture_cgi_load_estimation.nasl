#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(33817);
 script_version ("$Revision: 1.4 $");
 
 script_name(english: "Web Application Tests : load estimation");
 
 script_set_attribute(attribute:"synopsis", value:
"Load estimation for web application tests." );
 script_set_attribute(attribute:"description", value:
"This script computes the maximum number of requests that would be done 
by the generic web tests, depending on miscellaneous options. 
It does not perform any test by itself.

The results can be used to estimate the duration of these tests, or 
the complexity of additional manual tests.

Note that the script does not try to compute this duration as it would
depend upon external factors such as the network and web servers loads.");

 script_set_attribute(attribute:"solution", value: "n/a" );
 script_set_attribute(attribute:"risk_factor", value: "None" );

script_end_attributes();

 script_summary(english: "Estimate the number of requests done by the web app tests");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("global_settings.nasl", "web_app_test_settings.nasl", "webmirror.nasl");
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_names.inc");

if (! get_kb_item("Settings/enable_web_app_tests")) exit(0);

embedded = get_kb_item("Settings/HTTP/test_embedded");

max_tested_val = get_kb_item("Settings/HTTP/max_tested_values");
if (max_tested_val <= 0) max_tested_val = 3;

nb_attacks = make_array(
 "EX", 14,	# torture_cgi_command_exec.nasl
 "DT", 21,	# torture_cgi_directory_traversal.nasl
 "XS", 7,	# torture_cgi_cross_site_scripting.nasl
# "PX", 4,	# torture_cgi_persistent_XSS.nasl
 "SI", 25,	# torture_cgi_SSI_injection.nasl
# "LI", 1,	# torture_cgi_ldap_injection.nasl
 "FS", 1,	# torture_cgi_format_string.nasl
# "BS", 3,	# torture_cgi_blind_sql_injection.nasl
 "HI", 1,	# torture_cgi_header_injection.nasl
 "WI", 1	# torture_cgi_remote_file_inclusion.nasl
);
# SC, SH use a different system

if (report_paranoia > 1)
{
 nb_attacks["XS"] += 1;
}
if (thorough_tests)
{
 nb_attacks["XS"] += 9;
 nb_attacks["LI"] += 3;
}

port = get_http_port(default: 80, embedded: embedded);

cgis = get_kb_list(strcat("www/", port, "/cgis"));
if (isnull(cgis)) exit(0);
cgis = make_list(cgis);

foreach k (keys(nb_attacks))
{
 tot_single[k] = 0; tot_all_c[k] = 0; tot_all_p[k] = 0; tot_some_c[k] = 0; tot_some_p[k] = 0;
 totP_single[k] = 0; totP_all_c[k] = 0; totP_all_p[k] = 0; totP_some_c[k] = 0; totP_some_p[k] = 0;
}

num_cgi = 0;

function add_overflow(a, b)
{
 local_var	c;
  if (a == '>2G' || b == '>2G') return '>2G';
  c = a + b;
  if (c < a || c < b) return '>2G';
  return c;
}

function mul_overflow(a, b)
{
 local_var	c;

  if ( a == 0 || b == 0 ) return 0;
  if (a == '>2G' || b == '>2G') return '>2G';
  c = a * b;
  if (c < a || c < b) return '>2G';
  return c;
}

foreach cgi (cgis)
{
  r = eregmatch(string: cgi, pattern: "^(.+) - (.*)$");
  if (isnull(r)) continue;
  cgi_name = r[1];
  cgi = r[2]; 

  num_args = 0;
  num_vals = make_list();
  num_act = make_list();

  d = get_kb_list(strcat("www/", port, "/form-action", cgi_name));
  if (isnull(d)) num_act = 1;
  else num_act = max_index(d);
  if (num_act == 0) num_act = 1;

  while (strlen(cgi) > 0)
  {
    r = eregmatch(string: cgi, pattern: "^([^ ]*) \[([^]]*)\] (.*)$");
    if (isnull(r))
    {
      r = eregmatch(string: cgi, pattern: "^([^\[\]]*) \[([^]]*)\] (.*)$");
      if (isnull(r))
      {
        err_print("Cannot parse: ", cgi);
        break;
      }
    }

    cgi = r[3];

    d = get_kb_list(strcat("www/", port, '/cgi-params', cgi_name, "/", r[1]));
    if (isnull(d))
    {
      d = make_list(r[2]);
    }
    else
      d = list_uniq(make_list(r[2], make_list(d)));
    n = max_index(d);
    if (n == 0) n = 1;
    num_vals[num_args] = n;

    num_args ++;
  }
  foreach k (keys(nb_attacks))
  {
    nb_all_c = 0; nb_all_p = 0;
    nb_some_c = 0; nb_some_p = 0;
    nb_single = num_args * nb_attacks[k];

    for (i = 0; i < num_args; i ++)
    {
      a = nb_attacks[k]; t = 1;
      aa = a; tt = t;
      for (j = 0; j < num_args; j ++)
      {
        if (i != j)
	{
	  n = num_vals[j];
	  a = mul_overflow(a: a, b: n);
	  if (n > 1)
	    t += n - 1;

	  if (n > max_tested_val)
	   n = max_tested_val;
	  aa = mul_overflow(a: aa, b: n);
	  if (n > 1)
	    tt += n - 1;
	}
      } 
      nb_all_c = add_overflow(a: nb_all_c, b: a);
      nb_all_p = add_overflow(a: nb_all_p, b: nb_attacks[k] * t);
      nb_some_c = add_overflow(a: nb_some_c, b: aa);
      nb_some_p = add_overflow(a: nb_some_p, b: nb_attacks[k] * tt);
    }

    debug_print(level: 2, "CGI=", cgi_name, " - N=", num_args, " - AP=", nb_all_p, " - AC=", nb_all_c, " - SP=", nb_some_p, " - SC=", nb_some_c);

    tot_single[k] = add_overflow(a: tot_single[k], b: nb_single);
    tot_all_c[k] = add_overflow(a: tot_all_c[k], b: nb_all_c);
    tot_some_c[k] = add_overflow(a: tot_some_c[k], b: nb_some_c);
    tot_all_p[k] = add_overflow(a: tot_all_p[k], b: nb_all_p);
    tot_some_p[k] = add_overflow(a: tot_some_p[k], b: nb_some_p);

    totP_single[k] = add_overflow(a: totP_single[k], b: mul_overflow(a: nb_single, b: num_act));
    totP_all_c[k] = add_overflow(a: totP_all_c[k], b: mul_overflow(a: nb_all_c, b: num_act));
    totP_some_c[k] = add_overflow(a: totP_some_c[k], b: mul_overflow(a: nb_some_c, b: num_act));
    totP_all_p[k] = add_overflow(a: totP_all_p[k], b: mul_overflow(a: nb_all_p, b: num_act));
    totP_some_p[k] = add_overflow(a: totP_some_p[k], b: mul_overflow(a: nb_some_p, b: num_act));
  }
}

report = 
"Here are the estimated number of requests in miscellaneous modes
for the GET method only :
[Single / Some Pairs / All Pairs / Some Combinations / All Combinations]

";
foreach k (keys(nb_attacks))
{
  n = torture_cgi_name(code: k);
  report = strcat(report, n, crap(data: ' ', length: 29 - strlen(n)), 
':  S=', tot_single[k], crap(data: ' ', length: 9 - strlen(strcat(tot_single[k]))),
'  SP=', tot_some_p[k], crap(data: ' ', length: 9 - strlen(strcat(tot_some_p[k]))),
'  AP=', tot_all_p[k], crap(data: ' ', length: 9 - strlen(strcat(tot_all_p[k]))),
'  SC=', tot_some_c[k], crap(data: ' ', length: 9 - strlen(strcat(tot_some_c[k]))),
' AC=', tot_all_c[k], '\n');
}

report = strcat(report, 
"
Here are the estimated number of requests in miscellaneous modes
for both methods (GET & POST) :
[Single / Some Pairs / All Pairs / Some Combinations / All Combinations]

");
foreach k (keys(nb_attacks))
{
  n = torture_cgi_name(code: k);
  report = strcat(report, n, crap(data: ' ', length: 29 - strlen(n)), 
':  S=', add_overflow(a: totP_single[k], b: tot_single[k]), crap(data: ' ', length: 9 - strlen(strcat(totP_single[k]))),
'  SP=', add_overflow(a: totP_some_p[k], b: tot_some_p[k]), crap(data: ' ', length: 9 - strlen(strcat(totP_some_p[k]))),
'  AP=', add_overflow(a: totP_all_p[k], b: tot_all_p[k]), crap(data: ' ', length: 9 - strlen(strcat(totP_all_p[k]))),
'  SC=', add_overflow(a: totP_some_c[k], b: tot_some_c[k]), crap(data: ' ', length: 9 - strlen(strcat(totP_some_c[k]))),
' AC=', add_overflow(a: totP_all_c[k], b: tot_all_c[k]), '\n');
}

security_note(port: port, extra: report);
if (COMMAND_LINE) display('port=', port, '\n', report);
