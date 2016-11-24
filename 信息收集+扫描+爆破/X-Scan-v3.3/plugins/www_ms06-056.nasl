#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(24245);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2006-3436");
 script_bugtraq_id(20337);
 script_xref(name:"OSVDB", value:"29431");

 script_name(english:"MS06-056: Vulnerabilities in ASP.NET could allow information disclosure (922770) (uncredentialed check)");
 script_summary(english:"Determines the version of the ASP.Net DLLs via HTTP");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote .Net Framework is vulnerable to a cross-site scripting\n",
   "attack."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running a version of the ASP.NET framework affected\n",
   "by a cross-site scripting vulnerability that could allow an attacker\n",
   "to execute arbitrary code in the browser of the users visiting the\n",
   "remote web site."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows 2000, XP and \n",
   "2003 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms06-056.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("dotnet_framework_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

ver = get_kb_item("www/" + port + "/ASP.NET_Version");
if ( ! ver ) exit(0);

v = split(ver, sep:'.', keep:FALSE);
for ( i = 0 ; i < max_index(v) ; i ++ ) v[i] = int(v[i]);

if ( ! isnull(v) ) 
       if ( (v[0] == 2 && v[1] == 0 && v[2] == 50727 && v[3] < 210 ) )
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

