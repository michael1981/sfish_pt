#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14375);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2004-1743");
 script_bugtraq_id(11034);
 script_xref(name:"OSVDB", value:"9174");
 script_xref(name:"Secunia", value:"12372");
 
 script_name(english:"Easy File Sharing Web Server disk_c Virtual Folder Request Arbitrary File Access");
 script_summary(english:"Checks /disk_c");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has an arbitrary file read vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running Easy File Sharing Web Server, a web server\n",
     "package designed to facilitate file sharing.\n\n",
     "There is a flaw in the remote version of this software which may allow\n",
     "a remote attacker to read arbitrary files on the remote host."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0335.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "There are no known fixes at this time.  Consider using a different\n",
     "product."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
banner = get_http_banner(port:port);

if ( "Server: Easy File Sharing Web Server" >< banner )
{
  url = '/disk_c/boot.ini';
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  if(egrep(pattern:"\[boot loader\]", string:res[2]))
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus detected this by requesting the following URL :\n\n",
        "  ", build_url(qs:url, port:port), "\n"
      );

      if (report_verbosity > 1)
        report += string("\nWhich revealed :\n\n", res[2], "\n");

      security_hole(extra:report, port:port);
    }
    else security_hole(port);
  }
}
 
