#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(39463);
 script_version("$Revision: 1.4 $");
 
 script_name(english: "HTTP Server Cookies Set");
 
 script_set_attribute(attribute:"synopsis", value:
"Some cookies have been set by the web server." );
 script_set_attribute(attribute:"description", value:
"HTTP cookies are pieces of information that are presented by web 
servers and are sent back by the browser.
As HTTP is a stateless protocol, cookies are a possible mechanism to 
keep track of sessions.

This plugin displays the list of the HTTP cookies that were set by the 
web server when it was crawled." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 script_summary(english:"Displays set cookies"); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("webmirror.nasl", "DDI_Directory_Scanner.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

cookies_fields = make_list("domain", "path", "port", "name", "value", "version", "expires", "comment", "secure", "httponly");

comments = make_array(
	 "ASPSESSIONID", "IIS",
	 "CFID", "ColdFusion",
	 "CFTOKEN", "ColdFusion", 
	 "JSESSIONID", "Tomcat(servlet/jsp engine)",
	 "PHPSESSIONID", "PHP",
	 "SESSIONID", "Apache",
	 "SMSESSION", "Siteminder" );
# Other = JservSessionID, JWSESSIONID, SESSID, SESSION,SID,session_id

port = get_http_port(default: 80);

cj = strcat("webmirror-", port);
load_cookiejar(jar: cj);

kl = get_http_cookie_keys(name_re: ".*");
if (isnull(kl)) exit(0);

report = "";

foreach k (kl)
{
 c = get_http_cookie_from_key(k);
 if (isnull(c)) continue;
 n = c['name'];
 if (! isnull(n) && comments[n])
   report = strcat(report, '\nThis cookie was set by ', comments[n], ' :\n');
 else 
  report = strcat(report, '\n');
 foreach f (cookies_fields)
 {
  if ( ! isnull(c[f]) )
# && (f != 'secure' && f != 'httponly' || c[f]) )
   report = strcat( report, f, 
   	    	    crap(data: ' ', length: 8 - strlen(f)), ' = ', 
		    c[f], '\n');
 }
}

if (report)
{
 if (NASL_LEVEL < 3000)
  security_note(port: port, data: report);
 else
  security_note(port: port, extra: report);
 if (COMMAND_LINE) display(report);
}

