#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35974);
  script_version("$Revision: 1.3 $");
 
  script_name(english:"AWStats Detection");
  script_summary(english:"Looks for AWStats awstats.pl");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a log analysis application written in
Perl." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AWStats, an open source log analysis tool
written in Perl used to generate advanced graphic reports.");
 script_set_attribute(attribute:"see_also", value:"http://awstats.sourceforge.net/" );
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_set_attribute(attribute:"solution", value: "n/a");
 script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/awstats", "/stats", "/awstats/cgi-bin", "/statistics", "/awstats-cgi", "/tools", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  url = string(dir, "/awstats.pl");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);
 
  if('generator" content="AWStats' >< res[2] || 
     'description" content="Awstats - Advanced Web Statistics for' >< res[2] ||
     'AWStats UseFramesWhenCGI parameter' >< res[2] ||
     'Check config file, permissions and AWStats documentation' >< res[2]
    )
  {
    ver = NULL;
    # Check if we can get the version.
    matches = egrep(pattern:"(content=.AWStats .+ from config file|Advanced Web Statistics ([0-9]+.[0-9]+ *.*) - Created by awstats)", string:res[2]);
    if (matches)
    {
      foreach match (split(matches ,keep:FALSE))
      {
        if ("from config file" >< match)
          pat = "content=.AWStats ([0-9]+.*) from config file";
        else
          pat =  "Advanced Web Statistics ([0-9]+.[0-9]+ *.*) - Created by awstats";

         item = eregmatch(pattern:pat, string:match, icase:TRUE);
         if (!isnull(item) )
         {
            ver = item[1];
            break;
         }
      }
    }

    if(isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
       name:string("www/", port, "/AWStats"), 
       value:string(ver, " under ", dir)
    );
 
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;

    # Scan for multiple installations only if "Thorough Tests" is checked.
    if (installs && !thorough_tests) break;
  }
}

# Report findings.
if (max_index(keys(installs)))
{
  if (report_verbosity > 0)
  {
    info = "";
    n = 0;
    foreach ver (sort(keys(installs)))
    {
      info += '  Version : ' + ver + '\n';
      foreach dir (sort(split(installs[ver], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = dir + 'awstats.pl';
        else url = dir + '/' + 'awstats.pl';
        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of AWStats was';
    else report += 's of AWStats were';
    report += ' detected on the remote host :\n\n' + info;
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
