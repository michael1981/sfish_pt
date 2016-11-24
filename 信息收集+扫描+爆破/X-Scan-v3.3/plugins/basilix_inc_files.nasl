#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10601);
 script_bugtraq_id(2198);
 script_cve_id("CVE-2001-1044");
 script_xref(name:"OSVDB", value:"497");
 script_version ("$Revision: 1.21 $");
 
 script_name(english:"Basilix Webmail .class / .inc Direct Request Remote Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"It is possible to download the include files on the remote BasiliX
webmail service.  An attacker may use these to obtain the MySQL
authentication credentials." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityoffice.net/articles/basilix/index.php" );
 script_set_attribute(attribute:"solution", value:
"Put a handler in your web server for the .inc and .class files." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 
 summary["english"] = "Checks for the presence of include files";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/basilix"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  foreach file (make_list("/inc/sendmail.inc", "class/mysql.class")) {
    w = http_send_recv3(method:"GET", item:string(dir, file), port:port);
    if (isnull(w)) exit(0);
    r = w[2];

    if("BasiliX" >< r)
     {
      if("This program is free software" >< r) 
       {
        security_warning(port);
        exit(0);
       }
     }
  }
}
