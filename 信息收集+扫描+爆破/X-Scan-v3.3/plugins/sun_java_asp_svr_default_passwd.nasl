#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33437);
 script_version ("$Revision: 1.5 $");

 script_name(english:"Sun Java ASP Server Default Admin Password");
 script_summary(english:"Attempts to access remote ASP server with default admin credentials");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server can be accessed with default admin credentials." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sun Java ASP server. 

It is possible to access the remote server with default admin
credentials." );
 script_set_attribute(attribute:"see_also", value:"http://docs.sun.com/source/817-2514-10/index.html" );
 script_set_attribute(attribute:"solution", value:
"Follow the steps outlined in the vendor advisory referenced above to
change the admin password immediately." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_require_ports("Services/www", 5100);
 script_dependencies("http_version.nasl");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

#
# The script code starts here
#

port = get_http_port(default:5100);

# Request for admin page
r = http_send_recv3(method: "GET", item:"/caspadmin/index.asp", port:port, username: "", password: "");
if (isnull(r)) exit(0);


if ("401 Authorization Required" ><  r[0] && 
    "ASP Management Server"	>< r[1]+r[2]
   )
{
  # Try default combinations.
  combinations = make_list("admin:root","admin:admin","admin:password");
   
  foreach combination (combinations)
  {
   v = split(combination, sep: ':', keep: 0);
   r = http_send_recv3(method: "GET", item:"/caspadmin/index.asp", port:port, 
     username: v[0], password: v[1]);
    if("Location: /caspadmin/server.props.asp" >< r[1] && 
       "Set-Cookie:" >< r[1]
    ) 
    {
      if (report_verbosity)
      { 
       report = string ("\n",
	"Nessus was able to login into the remote ASP server with\n",
        "default admin credentials : ",combination,"\n\n",
        "Please change the password immediately\n\n"
	);	
      security_hole(port:port,extra:report);
     } 
     else
      security_hole(port);
    exit(0);
   }
  }
}

