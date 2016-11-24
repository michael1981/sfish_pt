# Written by Gareth M. Phillips - SensePost PTY ltd
# www.sensepost.com


include("compat.inc");

if (description) 
{
script_id(26056);
script_version("$Revision: 1.6 $");

script_name(english:"AWStats is Openly Accessible");

summary["english"] = "AWStats seems to be openly accessible to any user";
script_summary(english:summary["english"]);
 script_set_attribute(attribute:"synopsis", value:
"The remote web server allows access to its usage reports.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of AWStats that seems to be
accessible to the entire Internet.  Exposing AWStats unprotected to
the entire Internet will aid an attacker in gaining further knowledge
of web server and contents there in.  An attacker may gain access to
administrative backends or private files hosted on the server." );
 script_set_attribute(attribute:"solution", value:
"AWStats should be either restricted to authorised networks/hosts only,
or protected with some form of Basic-Auth." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();


script_category(ACT_GATHER_INFO);
script_family(english:"CGI abuses");

script_copyright(english:"This script is Copyright (C) 2007-2009 SensePost");
script_dependencies("awstats_detect.nasl");

script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");

exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/AWStats"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches))
{
  dir = matches[2];
  info = NULL;

  # Trying to retrieve the AWStats default File.
  url = dir+"/awstats.pl";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);
  if(egrep(pattern:"^HTTP.* 401 .*", string:res)) exit(0);

  if ('src="awstats.pl?framename=mainleft' >< res || egrep(pattern:'content="[aA]wstats - Advanced Web Statistics', string:res))
    info += ' ' + url + '\n';
}

if (!isnull(info))
{
  report = string(
    "\n",
    "AWStats' default page, awstats.pl, was found to exist on the web\n",
    "server under the following URL(s) :\n",
    "\n",
     info
     );
   security_note(port:port, extra:report); exit(0);
}
