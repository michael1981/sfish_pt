#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19235);
  script_version("$Revision: 1.11 $");

  script_bugtraq_id(14160);
  script_xref(name:"OSVDB", value:"17742");
  script_xref(name:"OSVDB", value:"17743");

  script_name(english:"Gossamer Threads Links < 3.0.4 Multiple Script XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains CGI scripts that are prone to cross-
site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Gossamer Links, a web links management tool
from Gossamer Threads and written in Perl. 

The installed version of Gossamer Links fails to properly sanitize
user-supplied input to various parameters of the 'user.cgi' and
'add.cgi' scripts, which are used by an administrator.  By leveraging
this flaw, an attacker may be able to cause arbitrary HTML and script
code to be executed by a user's browser within the context of the
affected application, leading to cookie theft and similar attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67268918" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gossamer Links 3.0.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in Gossamer Links < 3.0.4");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '");</script>';
# nb: the url-encoded version is what we need to pass in.
exss = '%3Cscript%3Ealert("' + SCRIPT_NAME + '")%3B%3C%2Fscript%3E';


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Check whether a flawed script exists.
  #
  # nb: check for add.cgi since user.cgi sometimes doesn't exist.
  r = http_send_recv3(method: "GET", item:string(dir, "/add.cgi"), port:port);
  if (isnull(r)) exit(0);

  # If it does...
  if (egrep(string: r[2], pattern:'<FORM action=".+/add.cgi" method=POST>')) {
    # Identify a category.
    pat = 'SELECT NAME="Category" +SIZE=1><OPTION>.+<OPTION>([^<]+)<OPTION>';
    matches = egrep(pattern:pat, string: r[2], icase:TRUE);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        cat = eregmatch(pattern:pat, string:match);
        if (!isnull(cat)) {
          cat = cat[1];
          break;
        }
      }
    }

    if (isnull(cat)) {
      debug_print("couldn't select a category for adding a link!", level:0);
    }
    else {
      # Try to exploit one of the flaws.
      postdata = string(
        "Title=", SCRIPT_NAME, "+Test&",
        "URL=http://www.nessus.org/&",
        # nb: this really should be url-encoded!
        "Category=", cat, "&",
        "Description=Nessus+is+checking+for+flaws+in+Gossamer+Links&",
        "Contact+Name=", exss, "&",
        "Contact+Email=na@", get_host_name()
      );
      r = http_send_recv3(method: "POST", item: strcat(dir, "/add.cgi"),
      	version: 11, data: postdata, port: port,
        # nb: this script needs a valid referer!
	add_headers: make_array("Referer", strcat("http://", get_host_name(), dir, "/add.cgi"),
        "Content-Type", "application/x-www-form-urlencoded") );
      if (isnull(r)) exit(0);

      # There's a problem if we see our XSS as the Contact Name.
      if (egrep(string: r[2], pattern:string("Contact Name: +", xss))) {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
      }
    }
  }
}
