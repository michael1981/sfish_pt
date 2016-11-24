#
# (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
 script_id(16335);
 script_version("$Revision: 1.7 $");
 
 script_name(english:"PHP-Fusion Detection");
 script_summary(english:"Checks the location of the remote PHP-Fusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a content management system written in
PHP." );
 script_set_attribute(attribute:"description", value:
"This script determines if PHP-Fusion is installed on the remote host
and, if so, stores its location in the KB. 

PHP-Fusion is a light-weight, open-source content management system
written in PHP." );
 script_set_attribute(attribute:"see_also", value:"http://www.php-fusion.co.uk/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
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

if(!can_host_php(port:port))exit(0);

info = NULL;

if (thorough_tests) dirs = list_uniq(make_list("/fusion", "/php-files", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 r = http_send_recv3(method:"GET", item:string(dir, "/news.php"), port:port);
 if (isnull(r)) exit(0);
 res = r[2];

 if (egrep(pattern:"Powered by.*PHP-Fusion", string:res))
 {
   pat = ".*PHP-Fusion.*v([0-9][.,][0-9.,]+) .* 20[0-9][0-9]-20[0-9][0-9]";
   matches = egrep(pattern:pat, string:res);
   foreach match (split(matches)) {
     match = chomp(match);
     ver = eregmatch(pattern:pat, string:match);
     if (!isnull(ver)) {
       ver = ver[1];
       break;
     }
   }
   if (isnull(ver)) ver = "unknown";
   if ( dir == "" ) dir = "/";

   set_kb_item(name:"www/" + port + "/php-fusion", value:ver + " under " + dir);
   info += ' - ' + ver + ' under ' + dir + '\n';

   if (!thorough_tests) break;
 }
}

if ( info )
{
  info = '\n' +
    'The remote web site is running the following version(s) of this software :\n\n' +
    info;
  security_note(port:port, extra:info);
}
