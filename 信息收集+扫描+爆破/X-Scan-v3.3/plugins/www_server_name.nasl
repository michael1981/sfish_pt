#
# (C) Tenable Network Security, Inc.
#

########################


include("compat.inc");

if(description)
{
 script_id(11239);
 script_version ("$Revision: 1.18 $");
 #script_bugtraq_id(2979);
 #script_cve_id("CVE-2000-0002");
 
 script_name(english:"Web Server Crafted Request Vendor/Version Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server that may be leaking information." );
 script_set_attribute(attribute:"description", value:
"The web server running on the remote host appears to be hiding its version
or name, which is a good thing. However, using a special crafted request,
Nessus was able to discover it." );
 script_set_attribute(attribute:"solution", value:
"Fix the web server's configuration." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
 script_summary(english:"Tries to discover the web server name");
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

r = http_send_recv3(port: port, method: "GET", item: "/");


# If anybody can get the server name, exit
srv = '^Server: *([^ \t\n\r]+)';
if (egrep(string: r[1], pattern: srv)) exit(0);

i = 0;
req[i++] = 'HELP\r\n\r\n';
req[i++] = 'HEAD / \r\n\r\n';
req[i++] = 'HEAD / HTTP/1.0\r\n\r\n';
req[i++] = strcat('HEAD / HTTP/1.1\r\nHost: ', get_host_name(), '\r\n\r\n');

for (i = 0; req[i]; i=i+1)
{
  w = http_send_recv_buf(port: port, data: req[i]);
  if (! isnull(w))
  {
    v = eregmatch(string: w[1], pattern: srv);
    if (! isnull(v))
    {
     s1 = v[1];
     rep = "
Nessus was able to gather the following information from the web server :
" + s1;
     r = strcat(w[0], w[1]);
     security_note(port:port, extra: rep);
     debug_print("Request: ", chomp(req[i]), " - Server: ", s1);

      # We check before: creating a list is not a good idea
      sb = string("www/banner/", port);
      if (! get_kb_item(sb))
	{
	 if ( defined_func("replace_kb_item") )
        	replace_kb_item(name: sb, value: r);
	  else
        	set_kb_item(name: sb, value: r);
	}
      else
      {
        sb = string("www/alt-banner/", port);
        if (! get_kb_item(sb))
          set_kb_item(name: sb, value: r);
      }
      exit(0);
    }
  }
}
