#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42822);
 script_version ("$Revision: 1.1 $");

 script_name(english:"Strict Transport Security (STS) Detection");
 script_summary(english:"Checks if the web server supports STS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server implements Strict Transport Security.");
 script_set_attribute(attribute:"description", value:
"The remote web server implements Strict Transport Security (STS). 
The goal of STS is to make sure that a user does not accidentally
downgrade the security of his or her browser. 

All unencryted HTTP connections are redirected to HTTPS.  The browser
is expected to treat all cookies as 'secure' and to close the
connection in the event of potentially insecure situations.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fb3aca6");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/16");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:443);

r = http_get_cache(port: port, item:"/");
if (isnull(r)) exit(0);

sts = egrep(string: r, pattern: "^Strict-Transport-Security:");
if (!sts) exit(0, "The web server on port "+port+" does not implement STS.");
else
{
  rep = strcat('\nThe STS header line is :\n\n', chomp(sts), '\n');
  security_note(port: port, extra: rep);
  set_kb_item(name:"www/"+port+"/STS", value:TRUE);
}
