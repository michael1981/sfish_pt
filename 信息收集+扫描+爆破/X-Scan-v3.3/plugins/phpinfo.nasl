#
# This script was written by Randy Matz <rmatz@ctusa.net>
#
# Improvement by rd: look in every dir for info.php and phpinfo.php
# not just in cgi-bin

# Changes by Tenable:
# - Revised plugin title (4/24/009)


include("compat.inc");

if(description)
{
 script_id(11229);
 script_version ("$Revision: 1.12 $");
 
 script_name(english:"Web Server info.php / phpinfo.php Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to an
information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"Many PHP installation tutorials instruct the user to create a PHP file
that calls the PHP function 'phpinfo()' for debugging purposes. 
Various PHP applications may also include such a file.  By accessing
such a file, a remote attacker can discover a large amount of
information about the remote web server, including :

  - The username of the user who installed php and if they
    are a SUDO user.

  - The IP address of the host.

  - The version of the operating system.

  - The web server version.

  - The root directory of the web server. 

  - Configuration information about the remote PHP 
    installation." );
 script_set_attribute(attribute:"solution", value:
"Remove the affected file(s)." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();


 script_summary(english:"Checks for phpinfo() output");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Randy Matz");
 script_family(english:"CGI abuses");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencies("http_version.nasl");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if (thorough_tests)
 dirs = get_kb_list(string("www/", port, "/content/directories"));
else
  dirs = cgi_dirs();
if(isnull(dirs))dirs = make_list("");
else dirs = list_uniq(make_list("", dirs));

rep = NULL;
foreach dir (dirs)
{
 foreach script (make_list("/phpinfo.php", "/info.php"))
 {
   req = http_get(item:string(dir, script), port:port);
   res = http_keepalive_send_recv(port:port, data:req);
   if( res == NULL ) exit(0);
   if("<title>phpinfo()</title>" >< res)
	rep += '  - ' + build_url(port:port, qs:dir+script) + '\n';
 }
}


if(rep != NULL)
{
 if (report_verbosity)
 {
  if (max_index(split(rep)) > 1) s = "s that call";
  else s = " that calls";

  report = string(
   "\n",
   "Nessus discovered the following URL", s, " phpinfo() :\n",
   "\n",
   rep
  );
  security_warning(port:port, extra:report);
 }
 else security_warning(port);
}
