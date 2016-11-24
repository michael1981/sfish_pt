#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID


include("compat.inc");

if (description)
{
 script_id(11018);
 script_version("$Revision: 1.19 $");

 script_cve_id("CVE-2002-1769");
 script_bugtraq_id(3998);
 script_xref(name:"OSVDB", value:"831");
 script_xref(name:"OSVDB", value:"17652");
 script_xref(name:"OSVDB", value:"17653");
 script_xref(name:"OSVDB", value:"17654");
 script_xref(name:"OSVDB", value:"17655");
 script_xref(name:"OSVDB", value:"17656");
 script_xref(name:"OSVDB", value:"17657");
 script_xref(name:"OSVDB", value:"17658");
 script_xref(name:"OSVDB", value:"17659");
 script_xref(name:"OSVDB", value:"17660");
 script_xref(name:"OSVDB", value:"17661");
 script_xref(name:"OSVDB", value:"17662");
 script_xref(name:"OSVDB", value:"17663");
 script_xref(name:"OSVDB", value:"17664");
 script_xref(name:"OSVDB", value:"17665");
 script_xref(name:"OSVDB", value:"17666");
 script_xref(name:"OSVDB", value:"17667");
 script_xref(name:"OSVDB", value:"17668");
 script_xref(name:"OSVDB", value:"17669");
 script_xref(name:"OSVDB", value:"17670");
 script_xref(name:"OSVDB", value:"17671");

 script_name(english:"Microsoft Site Server Multiple Script Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server seems to leak information when some pages are 
accessed using the account 'LDAP_AnonymousUser' with the password 
'LdapPassword_1'.

Pages which leak information include, but are not limited to :
  
  - /SiteServer/Admin/knowledge/persmbr/vs.asp
  - /SiteServer/Admin/knowledge/persmbr/VsTmPr.asp
  - /SiteServer/Admin/knowledge/persmbr/VsLsLpRd.asp
  - /SiteServer/Admin/knowledge/persmbr/VsPrAuoEd.asp" );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=kb;EN-US;248840" );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=vulnwatch&m=101235440104716&w=2" );
 script_set_attribute(attribute:"solution", value:
"Install SP4 for Site Server 3.0." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 script_summary(english:"Determine if the remote host is vulnerable to a disclosure vuln.");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


function make_request(port, file)
{
  local_var r, req;

  req = string("GET ", file, " HTTP/1.1\r\n",
  		"Host: ", get_host_name(), "\r\n",
		"Authorization: Basic bmVzc3VzOm5lc3N1cw==\r\n\r\n");
  
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL ) exit(0);
  
  if (ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:r))
    exit(0);

  req = string("GET ", file, " HTTP/1.1\r\n",
  		"Host: ", get_host_name(), "\r\n",
		"Authorization: Basic TERBUF9Bbm9ueW1vdXM6TGRhcFBhc3N3b3JkXzE=\r\n\r\n");
  
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL ) exit(0);
  
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:r))
  {
    if(get_kb_item(string("www/no404/", port)))
     {
     if("Microsoft" >< r){
      	security_warning(port);
	exit(0);
     }
    }
    else {
      	security_warning(port);
	exit(0);
    }
  }
}
port = get_http_port(default:80);




if ( get_kb_item("www/no404/" + port) ) exit(0);

if( can_host_asp(port:port) )
{
 make_request(port:port, file:"/SiteServer/Admin/knowledge/persmbr/vs.asp"); 
 make_request(port:port, file:"/SiteServer/Admin/knowledge/persmbr/VsTmPr.asp"); 
 make_request(port:port, file:"/SiteServer/Admin/knowledge/persmbr/VsLsLpRd.asp"); 
 make_request(port:port, file:"/SiteServer/Admin/knowledge/persmbr/VsPrAuoEd.asp"); 
}
