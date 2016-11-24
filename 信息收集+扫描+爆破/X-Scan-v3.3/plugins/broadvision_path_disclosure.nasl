#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10686);
 script_bugtraq_id(2088);
 script_cve_id("CVE-2001-0031");
 script_xref(name:"OSVDB", value:"569");
 script_version ("$Revision: 1.18 $");
 script_name(english:"BroadVision One-To-One Enterprise Nonexistent JSP Request Path Disclosure");
 script_summary(english:"Tests for BroadVision Physical Path Disclosure Vulnerability");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The web application running on the remote host has a path disclosure\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "BroadVision reveals the physical path of the webroot when asked for\n",
     "a nonexistent .jsp file if it is configured incorrectly.  While\n",
     "displaying errors is useful for debugging applications, this feature\n",
     "should not be enabled on production servers.  A remote attacker could\n",
     "use this information to mount further attacks."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-12/0074.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Contact the vendor for a patch."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Actual check starts here...
# Check makes a request for nonexistent php3 file...

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

w = http_send_recv3(item:string("/nosuchfile-", rand(), "-", rand(), ".jsp"), 
 		method:"GET", port:port);
if (isnull(w)) exit(0);
r = strcat(w[0], w[1], '\r\n', w[2]);
if(egrep(string:r, pattern:".*Script /.*/nosuchfile-.*")) security_warning(port);

