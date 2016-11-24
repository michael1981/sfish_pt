#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(36074);
 script_version("$Revision: 1.3 $");

 script_cve_id("CVE-2009-0839", 
               "CVE-2009-0840",
               "CVE-2009-0841",
               "CVE-2009-0842",
               "CVE-2009-0843",
               "CVE-2009-1176",
               "CVE-2009-1177");
 script_bugtraq_id(34306);
 script_xref(name:"Secunia", value:"34520");

 script_name(english:"MapServer < 5.2.2 / 4.10.4 Multiple Flaws");
 script_summary(english:"Performs a banner check");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by 
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MapServer, an open source Internet map
server. The installed version of MapServer is affected by multiple 
flaws :

  - By creating a map file with overly long IMAGEPATH and/or
    NAME attribute(s), it may be possible to trigger a
    stack-based buffer overflow. (CVE-2009-0839)

  - It may be possible to trigger a heap-based buffer
    overflow by sending a HTTP POST request with
    'CONTENT_LENGTH' attribute set to '-1'. (CVE-2009-0840)
    Note: According to some reports this issue might have
    been incorrectly fixed, see references for more info.

  - It may be possible to create arbitrary files by 
    specifying file names to the 'id' parameter. 
    (CVE-2009-0841)
   
  - Provided an attacker has privileges to create symlinks
    on the file system, it may be possible to partially read
    the contents of arbitrary files. (CVE-2009-0842)

  - Provided an attacker has knowledge of a valid map file,
    it may be possible to determine if an arbitrary file 
    exists on the remote system. (CVE-2009-0843) 
  
  - Sufficient boundary checks are not performed on 'id'
    parameter in mapserver.c. An attacker may exploit 
    this issue to trigger a buffer overflow condition
    resulting in arbitrary code execution on the remote
    system. (CVE-2009-1176)

  - File maptemplate.c is affected by multiple stack-based
    overflow issues. (CVE-2009-1177)" );
 script_set_attribute(attribute:"see_also", value:"http://www.positronsecurity.com/advisories/2009-000.html" );
 script_set_attribute(attribute:"see_also", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/1861" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-03/0468.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.osgeo.org/pipermail/mapserver-users/2009-March/060600.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MapServer 5.2.2/4.10.4." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

if(report_paranoia < 2)
  exit(0);

port = get_http_port(default:80);

url = "/cgi-bin/mapserv.exe?map=nessus.map";

res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(0);

if("MapServer Message" >!< res[2])
{
 url  = "/cgi-bin/mapserv?map=nessus.map";
 res = http_send_recv3(method:"GET", item:url, port:port);
}

# Do a banner check.
if (
  'msLoadMap(): Unable to access file. (nessus.map)' >< res[2] &&
  egrep(pattern:"<!-- MapServer version [0-9]+\.[0-9]+\.[0-9]+ ", string:res[2])
)
{
 version = ereg_replace(pattern:".*<!-- MapServer version ([0-9]+\.[0-9]+\.[0-9]+) .*", string:res[2], replace:"\1");
 
 vers = split(version, sep:".", keep:FALSE);
 for (i=0; i<max_index(vers); i++)
    vers[i] = int(vers[i]);

 if ( ( vers[0] < 4 ) ||
      ( vers[0] == 4 && vers[1] < 10 ) ||
      ( vers[0] == 4 && vers[1] == 10 &&  vers[2] < 4 ) ||
      ( vers[0] == 5 && vers[1] < 2 ) ||
      ( vers[0] == 5 && vers[1] == 2 && vers[2] < 2 ) )
  {
    if(report_verbosity > 0)
    {
      report = string("\n",
                 "MapServer version ", version, " is running on the remote host.\n");
      security_hole(port:port,extra:report);
    }         
    else
     security_hole(port);
  }
}
