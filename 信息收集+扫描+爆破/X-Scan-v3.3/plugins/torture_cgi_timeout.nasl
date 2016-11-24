#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(39470);
 script_version ("$Revision: 1.6 $");

 script_name(english: "CGI Generic Tests Timeout");
 script_set_attribute(attribute:"synopsis", value:
"Some generic CGI attacks ran out of time." );
 script_set_attribute(attribute:"description", value:
"Some generic CGI tests ran out of time during the scan. 
The results may be incomplete." );
 script_set_attribute(attribute:"solution", value:
"Run your run scan again with a longer timeout or less ambitious
options :

  - Combinations of arguments values = 'all combinations' is much slower than 
   'two pairs' or 'single'.

  - Stop at first flaw = 'per port' is quicker.

  - In 'some pairs' or 'some combinations' mode, try reducing 
    web_app_tests.tested_values_for_each_parameter in nessusd.conf" );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_end_attributes();

 script_summary(english: "Generic CGI tests timed out");
 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("web_app_test_settings.nasl", "global_settings.nasl");
 script_require_ports("Services/www");
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

include("global_settings.inc");
include("torture_cgi_names.inc");

####

t = int(get_kb_item("Settings/HTTP/max_run_time"));
if (t <= 0) exit(0);

port = get_kb_item("Services/www");

r1 = ''; r2 = '';
l = get_kb_list("torture_CGI/timeout/"+port);
if (! isnull(l))
  foreach k (make_list(l)) r1 = strcat(r1, '- ', torture_cgi_name(code: k), '\n');

l = get_kb_list("torture_CGI/unfinished/"+port);
if (! isnull(l))
  foreach k (make_list(l))
    r2 = strcat(r2, '- ', torture_cgi_name(code: k), '\n');

r = '';
if (r1) r = strcat('The following tests timed out without finding any flaw :\n', r1, '\n');
if (r2) r = strcat(r, 'The following tests were interrupted and did not report all possible flaws :\n', r2, '\n');

if (r) security_note(port: port, extra: r);
