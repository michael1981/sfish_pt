#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(32381);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-1291");
  script_bugtraq_id(28055);
  script_xref(name:"OSVDB", value:"43041");
  script_xref(name:"Secunia", value:"29176");

  script_name(english:"ViewVC Direct Request CVSROOT Information Disclosure");
  script_summary(english:"Lists contents of CVSROOT directory");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a Python application that is affected\n",
      "by an information disclosure vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running ViewVC, a web-based tool for browsing CVS\n",
      "and Subversion repositories.\n",
      "\n",
      "The version of ViewVC installed on the remote host allows reading the\n",
      "contents of the 'CVSROOT' directory by navigating to it directly.  An\n",
      "attacker could leverage this issue to retrieve sensitive information.\n",
      "\n",
      "Note that there are also reportedly two other information disclosure\n",
      "vulnerabilities associated with this version of ViewVC which could\n",
      "lead to exposure of restricted content, although Nessus has not\n",
      "checked for them."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://viewvc.tigris.org/source/browse/viewvc/trunk/CHANGES?rev=HEAD"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to ViewVC 1.0.5 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/viewvc", "/cgi-bin/viewvc.cgi", "/viewvc.cgi", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Get the directory listing.
  url = string(dir, "/CVSROOT/");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If successful...
  if (
    'class="vc_header"' >< res[2] &&
    "Index of /CVSROOT</title" >< res[2]
  )
  {
    # Make sure it's supposed to be hidden.
    res2 = http_send_recv3(method:"GET", item:string(dir, "/"), port:port);
    if (isnull(res2)) exit(0);

    if (
      'class="vc_header"' >< res2[2] &&
      'CVSROOT/" title="View' >!< res2[2]
    )
    {
      if (report_verbosity > 0)
      {
       if (get_port_transport(port) > ENCAPS_IP)
        {
          if (port == 443) url = string("https://", get_host_name(), url);
          else url = string("https://", get_host_name(), ":", port, url);
        }
        else 
        {
          if (port == 80) url = string("http://", get_host_name(), url);
          else url = string("http://", get_host_name(), ":", port, url);
        }

        report = string(
          "\n",
          "Nessus was able to obtain a listing of the CVSROOT directory with the\n",
          "following URL :\n",
          "\n",
          "  ", url, "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
