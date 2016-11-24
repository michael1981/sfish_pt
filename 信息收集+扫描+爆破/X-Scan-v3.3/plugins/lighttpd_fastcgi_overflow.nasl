#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26057);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-4727");
  script_bugtraq_id(25622);
  script_xref(name:"OSVDB", value:"36933");

  script_name(english:"lighttpd mod_fastcgi HTTP Request Header Remote Overflow");
  script_summary(english:"Sends a long header to lighttpd");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be lighttpd running with the FastCGI
module (mod_fastcgi). 

The version of that module on the remote host appears to be
affected by a buffer overflow vulnerability.  By sending a specially-
crafted request with a long header, a remote attacker may be able to
exploit this issue to add or replace headers passed to PHP, such as
SCRIPT_FILENAME, which in turn could result in arbitrary code
execution." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b18fbfb0" );
 script_set_attribute(attribute:"solution", value:
"Either disable the FastCGI module or upgrade to lighttpd 1.4.18 or
later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_keys("www/lighttpd");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure the banner looks like lighttpd w/ FastCGI (or some type of PHP support).
banner = get_http_banner(port:port);
if (
  !banner || 
  "lighttpd/" >!< banner ||
  "X-Powered-By: PHP" >!< banner
) exit(0);


# Make sure the server itself works.
url = "/";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL) exit(0);


# If it does...
if (egrep(string:res, pattern:"^HTTP/.* 200 OK"))
{
  # Send the same request but with a long header.
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      # nb: the size of the environment needs to exceed FCGI_MAX_LENGTH, 
      #     as defined in src/fastcgi.h. By default, it's 0xffff so 
      #     this is probably more than what we need.
      "Nessus: ", crap(0xffff), "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem unless we get a 400 response.
  if (!egrep(string:res, pattern:"^HTTP/.* 400 "))
  {
    security_warning(port);
  }
}
