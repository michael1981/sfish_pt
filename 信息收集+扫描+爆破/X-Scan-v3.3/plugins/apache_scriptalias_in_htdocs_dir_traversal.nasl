#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(22203);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-4110");
  script_bugtraq_id(19447);
  script_xref(name:"OSVDB", value:"27913");

  script_name(english:"Apache on Windows mod_alias URL Validation Canonicalization CGI Source Disclosure");
  script_summary(english:"Tries to read source of print-env.pl with Apache for Windows");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The version of Apache for Windows installed on the remote host can be
tricked into disclosing the source of its CGI scripts because of a
configuration issue.  Specifically, if the CGI directory is located
within the document root, then requests that alter the case of the
directory name will bypass the mod_cgi cgi-script handler and be
treated as requests for ordinary files." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/442882/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Reconfigure Apache so that the scripts directory is located outside of
the document root." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );


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

port = get_http_port(default:80);

# Make sure the banner is from Apache.
#
# nb: if ServerTokens is set to anything other than "OS" or "Full",
#     it won't tell us that it's running under Windows.
banner = get_http_banner(port:port);
if (!banner || "Apache" >!< banner ) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw to read a CGI script.
  #
  # nb: printenv.pl is included by default.
  file = "printenv.pl";
  r = http_send_recv3(method:"GET", item:string(toupper(dir), "/", file), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if it looks like the source.
  if (
    "foreach $var (sort(keys(%ENV))) {" >< res &&
    egrep(pattern:"^#!.+/perl\.exe", string:res)
  )
  {
    report = string(
      "Here are the contents of the '", dir, "/", file, "' CGI script that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      res
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
