#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42823);
 script_version ("$Revision: 1.1 $");

 script_name(english:"Non-compliant Strict Transport Security (STS)");
 script_summary(english:"Checks if the web server supports STS correctly");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server implements Strict Transport Security
incorrectly.");
 script_set_attribute(attribute:"description", value:
"The remote web server implements Strict Transport Security.  However,
it does not respect all the requirements of the STS draft standard.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fb3aca6");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/16");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("httpver.nasl", "sts_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 443);

sts = get_kb_item("www/"+port+"/STS");
if (!sts) exit(0, "The web server on port "+port+" does not implement STS.");

t = get_port_transport(port);
nc = "";
if (t == ENCAPS_IP)
{
  security_note(port: port, extra: "\nThe Strict-Transport-Security header must not be sent over an\nunencrypted channel.");
} 
else if (port == 443)
{
  if (get_port_state(80))
  {
    r2 = http_get_cache(port: 80, item: "/");
    if (! egrep(string: r2, pattern: "^HTTP/1\.[01] 301 ") ||
          egrep(string: r2, pattern: "^Location: *https://", icase: 1))
      security_note(port: port, extra:"\nAll connections to the HTTP site must be redirected to the HTTPS site.");
  }
}
