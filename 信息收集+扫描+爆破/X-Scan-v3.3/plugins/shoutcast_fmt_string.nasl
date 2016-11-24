#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(16064); 
 script_version ("$Revision: 1.8 $");

 script_cve_id("CVE-2004-1373");
 script_bugtraq_id(12096);
 script_xref(name:"OSVDB", value:"12585");
 
 script_name(english:"SHOUTcast Server Filename Handling Format String");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote streaming audio server is vulnerable a format string\n",
   "attack."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "According to its banner, the version of SHOUTcast Server installed on\n",
   "the remote host is earlier than 1.9.5.  Such versions fail to validate\n",
   "requests containing format string specifiers before using them in a\n",
   "call to 'sprintf()'.  An unauthenticated remote attacker may be able\n",
   "to exploit this issue to execute arbitrary code on the remote host."
  )
 );
 script_set_attribute(
  attribute:"see_also",
  value:"http://archives.neohapsis.com/archives/bugtraq/2004-12/0366.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to SHOUTcast 1.9.5 or later."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();
 
 script_summary(english:"SHOUTcast version check");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

req = 'GET /content/dsjkdjfljk.mp3 HTTP/1.0\r\n\r\n';
ports = add_port_in_list(list:get_kb_list("Services/www"), port:8000);
foreach port (ports)
{
 if (get_port_state(port))
 {
  banner = http_keepalive_send_recv(port:port, data:req);
  if ( banner != NULL )
  {
  if (egrep(pattern:"SHOUTcast Distributed Network Audio Server.*v(0\.|1\.[0-8]\.|1\.9\.[0-4][^0-9])", string:banner) )
  {
   security_hole(port);
   exit(0);
  } 
  }
 }
}
