#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11678);
  script_version("$Revision: 1.13 $");
  script_cve_id("CVE-2003-0417");
  script_bugtraq_id(7717);
  script_xref(name:"OSVDB", value:"4662");

  script_name(english:"Super-M Son hServer URI Traversal Arbitrary File Access");
  script_summary(english:"Attempt to read an arbitrary file outside.");

   script_set_attribute(
    attribute:'synopsis',
    value:'Super-M Son hServer is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'Super-M Son hServer is vulnerable to a directory traversal.
It enables a remote attacker to view any file on the computer
with the privileges of the web server.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'This product is not supported by the vendor.  Use another web server.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=105417983711685&w=2'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


function check(req)
{
  local_var r;
  req = http_get(item:req, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if ( r == NULL ) exit(0);

  if(("[windows]" >< r)||
    ("[fonts]" >< r))
  {
        security_warning(port:port);
        return(1);
  }
 return(0);
}

dirs = cgi_dirs();
foreach dir (dirs)
{
 url1 = string(dir, "/.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./windows/win.ini");
 if(check(req:url1))exit(0);

 url2 = string(dir, "/.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./winnt/win.ini");
 if(check(req:url2))exit(0);
}
