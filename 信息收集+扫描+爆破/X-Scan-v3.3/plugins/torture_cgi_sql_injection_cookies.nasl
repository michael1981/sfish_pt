#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42426);
 script_version ("$Revision: 1.3 $");

 script_name(english: "CGI Generic SQL Injection Vulnerability (HTTP Cookies)");
 script_summary(english: "SQL injection techniques through HTTP cookies");

 script_set_attribute(attribute:"synopsis", value:
"A CGI application hosted on the remote web server is potentially
prone to SQL injection attack.");
 script_set_attribute(attribute:"description", value:
"By sending specially crafted HTTP cookies to one or more CGI scripts
hosted on the remote web server, Nessus was able to cause an error in
the underlying database.  This error suggests that the CGI script(s)
are prone to SQL injection attack. 

An attacker may be able to exploit this issue to bypass
authentication, read confidential data, modify the remote database, or
even take control of the remote operating system." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/SQL_injection" );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/securityreviews/5DP0N1P76E.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securitydocs.com/library/2651" );
 script_set_attribute(attribute:"solution", value:
"Modify the affected CGI scripts so that they properly escape
arguments." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/06");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(432000);	# Timeout is managed by the script itself
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_headers.inc");
include("torture_cgi_sql_inj_msg.inc");

single_quote = raw_string(0x27);
double_quote = raw_string(0x22);
postheaders = make_array("Content-Type", "application/x-www-form-urlencoded");

i = 0;
poison[i++] = single_quote;
poison[i++] = single_quote + "%22";
poison[i++] = "9%2c+9%2c+9";
poison[i++] = "bad_bad_value" + single_quote;
poison[i++] = "%3B";
poison[i++] = single_quote + " or 1=1-- ";
poison[i++] = " or 1=1-- ";
poison[i++] = "char(39)";
poison[i++] = "%27";
poison[i++] = "&#39;+AND+&#39;a&#39;<&#39;b";
poison[i++] = "--+";
poison[i++] = "#";
poison[i++] = "/*";
poison[i++] = double_quote;
poison[i++] = "%22";
poison[i++] = "%2527";
poison[i++] = single_quote + "+convert(int,convert(varchar,0x7b5d))+" + single_quote;
poison[i++] = "convert(int,convert(varchar,0x7b5d))";
poison[i++] = single_quote + "+convert(varchar,0x7b5d)+" + single_quote;
poison[i++] = "convert(varchar,0x7b5d)";
poison[i++] = single_quote + "%2Bconvert(int,convert(varchar%2C0x7b5d))%2B" + single_quote;
poison[i++] = single_quote + "%2Bconvert(varchar%2C0x7b5d)%2B" + single_quote;
poison[i++] = "convert(int,convert(varchar%2C0x7b5d))";
poison[i++] = "convert(varchar%2C0x7b5d)";
# from torturecgis.nasl
poison[i++] = "whatever)";
###
poison[i++] = "whatever="+single_quote;
poison[i++] = "whatever="+double_quote;
poison[i++] = "whatever/"+single_quote;
poison[i++] = "whatever/"+double_quote;
#

function test(meth, url, postdata, cgi, vul)
{
  local_var	r, i, h, p, a, rq, cookies_l, ck, old_cookie_val, txt;
  global_var	poison, port, stop_at_first_flaw;

  url = my_encode(url);
  if (COMMAND_LINE) debug_print("URL=", url, "\n");
  cookies_l = get_http_cookie_keys(port: port, path: cgi);
  if (isnull(cookies_l) || max_index(cookies_l) == 0)
  {
    debug_print("test(URL=", url, "): no cookie!\n");
    return -1;
  }

  foreach ck (cookies_l)
  {
    old_cookie_val = get_http_cookie_from_key(ck);
    for (p = 0; poison[p]; p ++)
    {
      set_http_cookie(key: ck, value: p);
      if (isnull(postdata))
        rq = http_mk_req(item: url, port:port, method: meth);
      else
        rq  = http_mk_req(item: url, data:postdata, port:port, method: meth);
      r = http_send_recv_req(req: rq, port:port);
      if(isnull(r))
      {
        set_http_cookie(key: ck, value: old_cookie_val);
        return 0;
      }

      txt = extract_pattern_from_resp(string: r[2], pattern: "GL");
      if (txt)
      {
        torture_cgi_remember(url: url, request: http_last_sent_request(), response: r,cgi: cgi, vul: vul, report: txt);
        set_http_cookie(key: ck, value: old_cookie_val);
	if (stop_at_first_flaw != "never")
          return 1;
	else
	  break;
      }
      set_http_cookie(key: ck, value: old_cookie_val);
    }
  }
  return -1;
}

run_injection_hdr(vul: "SC",
  ext_l: make_list("pl", "php", "php3", "php4", "php5", "cgi", "asp", "aspx"));
