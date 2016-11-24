#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20130);
  script_version("$Revision: 1.8 $");

  script_bugtraq_id(15251);
  script_xref(name:"OSVDB", value:"49507");

  script_name(english:"Comersus Cart /comersus/database/comersus.mdb Direct Request Datbase Disclosure");
  script_summary(english:"Checks for customer database vulnerability in Comersus Cart");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is prone to an
information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Comersus Cart, an ASP shopping
cart application. 

The version of Comersus Cart installed on the remote host fails to
restrict access to its customer database, which contains order
information, passwords, credit card numbers, etc.  Further, the data
in all likelihood can be decrypted trivially since the application
reportedly uses the same default password for each version of the
application to encrypt and decrypt data." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3010f669" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/comersus", "/store", "/shop", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw.
  r = http_send_recv3(method: 'HEAD', version: 11, port: port, item: "/database/comersus.mdb");
  if (isnull(r)) exit(0);

  # There's a problem if it looks like we can download the database.
  if ("Content-Type: application/x-msaccess" >< r[1]) {
    security_warning(port);
    exit(0);
  }
}
