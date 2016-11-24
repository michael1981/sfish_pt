
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(41058);
 script_version ("$Revision: 1.4 $");

 script_name(english:"Web Application Firewall Detection");
 script_summary(english: "Looks for WAF error messages(s)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is protected by a web application firewall." );
 script_set_attribute(attribute:"description", value:
"By analyzing error codes and messages returned from some web queries,
Nessus is able to determine that the remote web server is protected by
a web application firewall. 

Such protection may disrupt scan results.  Countermeasures have been
taken to make the scan as reliable as possible. " );
 script_set_attribute(attribute:"solution", value:
"To get a more comprehensive set of scan results, either whitelist the
Nessus server's IP address or scan from an unprotected location." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/23");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "httpver.nasl", "http_login.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

emb = 1;
port = get_http_port(default:80, embedded: emb);

banner = get_http_banner(port: port);

url_l = make_list(
"/robots.txt",
"/sitemap.xml",
"/.cobalt",
"/admin.back",
"/file",
"/wavemaster.internal"
);

headers_pat_l = make_array(
'^Server:[ \t]*Apache/.* mod_security/',	'mod_security',
'^ETag:[ \t]*rweb-err-no[0-9]',	'rWeb'
);

body_pat_l = make_array(
' alt="Powered by rWeb">', 'rWeb'
);

foreach u (url_l)
{
  r = http_send_recv3(port: port, method: "GET", item: u);
  if (isnull(r)) exit(1, "The web server failed to respond.");
  if (r[0] =~ '^HTTP/1\\.[01] 200 ')
  {
    foreach h (keys(headers_pat_l))
    {
      if (egrep(string: r[1], pattern: h, icase: 1))
      {
        set_kb_item(name: 'www/no403header/'+port, value: h);
        security_note(port: port, extra: '\nThe target is protected by :\n\n'+ headers_pat_l[h]);
	exit(0);
      }
      if (egrep(string: r[2], pattern: h, icase: 0))
      {
        set_kb_item(name: 'www/no403body/'+port, value: h);
        security_note(port: port, extra: '\nThe target is protected by :\n\n'+ headers_pat_l[h]);
	if (COMMAND_LINE) display('> ', headers_pat_l[h], '\n');
	exit(0);
      }
    }
  }
}

# Look for mod_security with the "standard" rule set. 
# We check that this is an Apache but the banner could be changed
if (report_paranoia > 0 || thorough_tests || "Apache" >< banner)
{
  r = http_send_recv3(port: port, method:"GET", item: "/");
  if (isnull(r)) exit(1, "The web server failed to respond.");
  if (r[0] =~ "^HTTP/1\.[01] 200 ")
  {
    r = http_send_recv3(port: port, method:"GET", item: "/",
      add_headers: make_array("User-Agent", "Nessus"));
    if (r[0] =~ "^HTTP/1\.[01] 404 ")
    {
      security_note(port: port, extra: '\nThe target might be protected by :\n\nmod_security');
      if (COMMAND_LINE) display('> mod_security\n');
      exit(0);
    }
  }
}

exit(1, "The web server is not protected by a web application firewall that this plugin knows about.");
