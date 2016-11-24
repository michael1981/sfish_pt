#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(40665);
 script_version("$Revision: 1.3 $");
 
 script_name(english: "Protected Web Page Detection");
 script_summary(english:"Displays pages that require authentication"); 
 
 script_set_attribute(attribute:"synopsis", value:
"Some web pages needs authentication." );
 script_set_attribute(attribute:"description", value:
"The remote web server requires HTTP authentication for the following
pages.  Several authentication schemes are available :

  - Basic is the simplest but the credential are sent in 
    clear text.

  - NTLM provides an SSO in MS environment, but it cannot be
    used on both the proxy and the web server. It is also 
    weaker than Digest.

  - Digest is a cryptographically strong scheme. Credentials 
    are never sent in clear text. They may still be cracked 
    by a dictionary attack though." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

 script_dependencie("webmirror.nasl", "DDI_Directory_Scanner.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80);

schemes_l = get_kb_list(strcat("www/", port, "/authentication_scheme"));
if (isnull(schemes_l)) exit(1, "The 'www/"+port+"/authentication_scheme' KB item is missing.");

report = "";
seen = make_array();

foreach s (schemes_l)
{
 k = tolower(s);
 if (seen[k]) continue;
 seen[k] = 1;

 report = strcat(report, '\nThe following pages are protected by the ', s, ' authentication scheme :\n\n');

 i = 0;
 while (1)
 {
   u = get_kb_item(strcat("www/", port, "/content/", k, "_auth/url/", i));
   if (isnull(u)) break;
   r = get_kb_item(strcat("www/", port, "/content/", k, "_auth/realm/", i));
   if (! r)
     report = strcat(report, u, ' - Realm = ', r, '\n');
   else
     report = strcat(report, u, '\n');
   i ++;
 }
 report = strcat(report, '\n');
}

if (report)
{
 if (NASL_LEVEL < 3000)
  security_note(port: port, data: report);
 else
  security_note(port: port, extra: report);
 if (COMMAND_LINE) display(report);
}
