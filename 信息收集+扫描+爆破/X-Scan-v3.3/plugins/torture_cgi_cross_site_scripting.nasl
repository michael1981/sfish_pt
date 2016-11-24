#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(39466);
 script_version ("$Revision: 1.11 $");


 script_name(english: "CGI Generic Cross-Site Scripting Vulnerability");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately sanitize 
request strings with malicious JavaScript.  By leveraging this issue, 
an attacker may be able to cause arbitrary HTML and script code
to be executed in a user's browser within the security context of the
affected site.
These XSS are likely to be 'non persistent' or 'reflected'." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Cross_site_scripting#Non-persistent" );
 script_set_attribute(attribute:"see_also", value:"http://jeremiahgrossman.blogspot.com/2009/06/results-unicode-leftright-pointing.html");
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the vendor 
for a patch or upgrade." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
 script_end_attributes();

 script_summary(english: "Tortures the arguments of the remote CGIs (XSS)");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses : XSS");
 script_dependencie("http_version.nasl", "webmirror.nasl", "cross_site_scripting.nasl", "web_app_test_settings.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(432000);	# Timeout is managed by the script itself
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");


####

i = 0; 
flaws_and_patterns = make_array(
 "<script>alert(42);</script>",   "ST:<script>alert(42);</script>",
 '<IMG SRC="javascript:alert(42);">', 'RE:<IMG( |%20)SRC="javascript:alert\\(42\\);">',
 "<BODY ONLOAD=alert(42)>",	 "ST:<BODY ONLOAD=alert(42)>",
  "<script > alert(42); </script >",   "RE:<script *> *alert\(42\); *</script *>",
# UTF-7 encoded
  "+ADw-script+AD4-alert(42)+ADw-/script+AD4-", "RE:<script>alert\(42\)</script>|.<.s.c.r.i.p.t.>.a.l.e.r.t.\(.4.2.\).<./.s.c.r.i.p.t.>",
  "<<<<<<<<<<foobar>>>>>",	"ST:<<foobar>>",
  ">>>>>>>>>>foobar<<<<<",	"ST:>>foobar<<"
);

if (report_paranoia > 1)
{
  flaws_and_patterns["< script > alert(42); </ script >"] = "RE:< *script *> *alert\(42\); *</ *script *>";
  # If the charset is not specified (and different from UTF-7), then this should work too
  flaws_and_patterns["+ADw-script+AD4-alert(42)+ADw-/script+AD4-"] = 
    "RE:\+ADw-script\+AD4-alert(42)\+ADw-/script\+AD4-|<script>alert\(42\)</script>|.<.s.c.r.i.p.t.>.a.l.e.r.t.\(.4.2.\).<./.s.c.r.i.p.t.>";
}

if (thorough_tests)
{
  flaws_and_patterns["%u00ABscript%u00BBalert(42);%u00AB/script%u00BB"] = 
    "RE:<script *> *alert\(42\); *</script *>";
  flaws_and_patterns["&#x3008;script&#x3009;alert(42);&#x3008;/script&#x3009;"] =
    "RE:<script *> *alert(42); *</script *>";
  flaws_and_patterns["U%2bFF1CscriptU%2bFF1Ealert(42);/U%2bFF1CscriptU%2bFF1E"] =
    "RE:<script *> *alert(42); *</script *>";
  flaws_and_patterns["&#x2039;script&#x203A;alert(42);&#x2039;/script&#x203A;"] =
    "RE:<script *> *alert(42); *</script *>";
  flaws_and_patterns["&#x2329;script&#x232Aalert(42);&#x2329;/script&#x232A"] =
    "RE:<script *> *alert(42); *</script *>";
  flaws_and_patterns["&#x27E8;script&#x27E9;alert(42);&#x27E8;/script&#x27E9;"] =
    "RE:<script *> *alert(42); *</script *>";
  flaws_and_patterns['<script\n>alert(42);</script\n>'] =
    'ST:<script\n>alert(42);</script\n>';
  flaws_and_patterns["+ADwAcwBjAHIAaQBwAHQAPgBhAGwAZQByAHQAKAA0ADIAKQA7ADwALwBzAGMAcgBpAHAAdAA+-"] =
    "RE:<script>alert\(42\);</script>|.<.s.c.r.i.p.t.>.a.l.e.r.t.\(.4.2.\).;.<./.s.c.r.i.p.t.>";
  flaws_and_patterns["%3Cscript%3Ealert(42)%3B%3C%2Fscript%3E"] = 
    "ST:<script>alert(42);</script>";
}

init_torture_cgi();

port = get_http_port(default:80, embedded: embedded);

if (get_kb_item(strcat("www/", port, "/generic_xss")))
  exit(0, 'The web server is vulnerable to generic cross-site scripting');
# if (stop_at_first_flaw == "port" && ! thorough_tests && get_kb_item(strcat("www/", port, "/XSS"))) exit(0);

report = torture_cgis(port: port, vul: "XS");

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
  if (COMMAND_LINE) display(report, '\n');
}
