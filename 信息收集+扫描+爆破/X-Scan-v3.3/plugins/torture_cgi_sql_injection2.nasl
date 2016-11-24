#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42479);
 script_version ("$Revision: 1.1 $");

 script_name(english: "CGI Generic SQL Injection Vulnerability (2nd pass)");
 script_summary(english: "Find SQL injections triggered by other attacks");

 script_set_attribute(attribute:"synopsis", value:
"A web application is potentially vulnerable to SQL injection." );
 script_set_attribute(attribute:"description", value:
"By providing specially crafted parameters to CGIs, Nessus was able to
get an error from the underlying database.  This error suggests that
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
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/12" );
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/enable_web_app_tests");
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

port = get_kb_item("Services/www");

report = "";
resp_l = get_kb_list("www/"+port+"/cgi_*/response/*");

foreach k (keys(resp_l))
{
  v = eregmatch(string: k, pattern: "/cgi_([A-Z][A-Z])/response/([0-9]+)");
  if (isnull(v)) continue;
  code = v[1]; nb = v[2];
  # Already known as an SQL injection?
  if (code == "SI" || code == "BS" || code == "SC" || code == "SH")
    continue;
  
  txt = extract_pattern_from_resp(string: resp_l[k], pattern: "GL");
  if (strlen(txt))
  {
    req = get_kb_item("www/"+port+"/cgi_"+code+"/request/"+nb);
    if (! req) continue;
    report = strcat(report, '-------- request --------\n', 
   req, 
   '------------------------\n\n-------- output --------\n', 
   txt, '------------------------\n\n');
  }
}

if (strlen(report) > 0)
{
  security_hole(port:port, extra: report);
  if (COMMAND_LINE) display(report, '\n');
}
