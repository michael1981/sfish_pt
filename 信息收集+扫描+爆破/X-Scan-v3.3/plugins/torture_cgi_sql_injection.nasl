#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11139);
 script_version ("$Revision: 2.3 $");
 script_name(english: "CGI Generic SQL Injection Vulnerability");

 script_set_attribute(attribute:"synopsis", value:
"A web application is potentially vulnerable to SQL injection." );
 script_set_attribute(attribute:"description", value:
"By providing specially crafted parameters to CGIs, Nessus was able to
get an error from the underlying database. This error suggests that
the CGI is affected by a SQL injection vulnerability.

An attacker may exploit this flaw to bypass authentication, read
confidential data, modify the remote database, or even take control of
the remote operating system." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/SQL_injection" );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/securityreviews/5DP0N1P76E.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securitydocs.com/library/2651" );
 script_set_attribute(attribute:"solution", value:
"Modify the relevant CGIs so that they properly escape arguments." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english: "Some common SQL injection techniques");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/enable_web_app_tests");
 script_timeout(432000);	# Timeout is managed by the script itself
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");
include("torture_cgi_sql_inj_msg.inc");


####

init_torture_cgi();

single_quote = raw_string(0x27);
double_quote = raw_string(0x22);

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
#
if (0)	# Disabled
{
poison[i++] = single_quote + "UNION" + single_quote;
poison[i++] = single_quote + "bad_bad_value";
poison[i++] = single_quote + "+AND+" + single_quote;
poison[i++] = single_quote + "WHERE";
poison[i++] = single_quote + "AND";
poison[i++] = single_quote + " or " + single_quote + "a" + single_quote + "=" + single_quote + "a";
poison[i++] = single_quote + ") or (" + single_quote + "a" + single_quote + "=" + single_quote + "a";
poison[i++] = single_quote + "+AND+1=1)";
poison[i++] = single_quote + "+AND+1=1))";
poison[i++] = single_quote + "+AND+1=1#";
poison[i++] = single_quote + "+AND+1=1)#";
poison[i++] = single_quote + "+AND+1=1))#";
poison[i++] = "&#39;)+AND+(&#39;a&#39;<&#39;b";
poison[i++] = "&#39;)+AND+(&#39;a&#39;<&#39;b&#39;)/*";
poison[i++] = "&#39;)+AND+(&#39;a&#39;<&#39;b&#39;))/*";
poison[i++] = single_quote + "+or+1=1/*";
poison[i++] = single_quote + "+or+1=1)/*";
poison[i++] = single_quote + "+or+1=1))/*";
}

flaws_and_patterns = make_array();
for (i = 0; ! isnull(poison[i]); i ++)
 flaws_and_patterns[poison[i]] = "GL";
poison = NULL;	# Free memory

####

port = get_http_port(default:80, embedded: embedded);

report = torture_cgis(port: port, vul: "SI");

if (strlen(report) > 0)
{
  security_hole(port:port, extra: report);
  if (COMMAND_LINE) display(report, '\n');
}

