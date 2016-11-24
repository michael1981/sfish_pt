#
# (C) Tenable Network Security, Inc.
#
# Ref: 
#  From: "Paul Craig" <pimp@brainwave.net.nz>
#  To: <bugtraq@securityfocus.com>
#  Subject: ImageFolio All Versions      (...)
#  Date: Thu, 5 Jun 2003 13:53:57 +1200



include("compat.inc");

if(description)
{
 script_id(11700);

 script_version("$Revision: 1.11 $");
 script_name(english:"ImageFolio Default Password");
 script_xref(name:"Secunia", value:"8964");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a web application that is uses a
default administrator password." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the ImageFolio image gallery manager.

This CGI is installed with a default administrator username and
password (Admin/ImageFolio) which has not been modifed.

An attacker may exploit this flaw to administrate this installation.

In addition to this, the CGI admin.cgi has a bug which may allow
an attacker to delete arbitrary files owned by the remote web server." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/secunia/2003-q2/0524.html" );
 script_set_attribute(attribute:"solution", value:
"Set a strong password for the administrator account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "Logs in as Admin/ImageFolio";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

function check(req)
{
  local_var res;
  local_var variables;

  variables = string("login=1&user=Admin&password=ImageFolio&save=Login");
  res = http_send_recv3(method:"POST",
                        item:req,
                        add_headers:make_array(
                                    "Content-Type", "application/x-www-form-urlencoded",
                                    "Content-Length", strlen(variables)),
                        data:variables,
                        port:port);
  if (isnull(res)) exit(1, "The remote web server did not respond.");
  if("<title>My ImageFolio Gallery Administration : </title>" >< res[2])
  {
    security_hole(port);
    exit(0);
  }
  return (0);
}

foreach dir (cgi_dirs())
{
 check(req:dir + "/admin/admin.cgi");
 exit(0);
}
