#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11397);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(7063);
 script_xref(name:"OSVDB", value:"54098");

 script_name(english:"VPOPMail for SquirrelMail vpopmail.php Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP script which may allow 
arbitrary code execution on the remote system." );
 script_set_attribute(attribute:"description", value:
"The remote host is running an old version of vpopmail.php 
(an extension to squirrelmail) which allows users to execute
arbitrary commands on the remote host with the same privileges 
as the web server the user is running as." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to VPOPMail 0.98 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Determines the version of vpopmail.php");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
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

if(!can_host_php(port:port))exit(0, "The remote web server does not support PHP.");

foreach d (make_list(cgi_dirs(), "/"))
{
  # UGLY UGLY UGLY
  res = http_send_recv3(method:"GET", item:"/vpopmail/README", port:port);

  if("VPOPMail Account Administration" >< res[2])
  {
    version = egrep(pattern:".*Version [0-9]\..*", string:res[2]);
    if ( version ) set_kb_item(name:"www/" + port + "/vpopmail/version", value:version);
    if(egrep(pattern:".*Version.*0\.([0-9]|[0-8][0-9]|9[0-7])[^0-9]", string:res[2]))
    	security_hole(port);
  }
}
