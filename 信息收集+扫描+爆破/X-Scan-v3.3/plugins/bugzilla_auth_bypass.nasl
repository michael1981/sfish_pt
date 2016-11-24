#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15562);
 script_cve_id("CVE-2004-1634", "CVE-2004-1635");
 script_bugtraq_id(11511);
 script_xref(name:"OSVDB", value:"11115");
 script_xref(name:"OSVDB", value:"11116");
 script_xref(name:"Secunia", value:"12939");
 script_version ("$Revision: 1.9 $");

 script_name(english:"Bugzilla < 2.16.7 / 2.18.0rc3 Multiple Information Disclosures");
 script_summary(english:"Checks for the presence of Bugzilla");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote bug tracker has multiple information disclosure\n",
     "vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote Bugzilla bug tracking system, according to its version\n",
     "number, is vulnerable to various flaws that may let an attacker bypass\n",
     "authentication or get access to private bug reports."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.bugzilla.org/security/2.16.6/"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to version 2.16.7 / 2.18.0rc3 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencie("bugzilla_detect.nasl");
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

version = get_kb_item(string("www/", port, "/bugzilla/version"));
if(!version)exit(0);


if(ereg(pattern:"(1\..*)|(2\.(0\..*|1[0-3]\..*|14\..*|15\..*|16\.[0-6]|17\..*|18\.0 *rc[0-2]))[^0-9]*$",
       string:version))security_warning(port);
