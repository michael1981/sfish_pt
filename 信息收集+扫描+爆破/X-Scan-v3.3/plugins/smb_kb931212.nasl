#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(25700);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2006-7192", "CVE-2007-0041", "CVE-2007-0042", "CVE-2007-0043");
 script_bugtraq_id(20753, 24778, 24791, 24811);
 script_xref(name:"OSVDB", value:"35269");
 script_xref(name:"OSVDB", value:"35954");
 script_xref(name:"OSVDB", value:"35955");
 script_xref(name:"OSVDB", value:"35956");

 script_name(english:"MS07-040: Vulnerabilities in .NET Framework Could Allow Remote Code Execution (931212) (uncredentialed check)");
 script_summary(english:"Determines the version of the .NET framework by looking at the IIS headers"); 

 script_set_attribute(
  attribute:"synopsis",
  value:"The remote .Net Framework is vulnerable to a code execution attack."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote web server is running a version of the ASP.NET framework\n",
   "that contains multiple vulnerabilities :\n",
   "\n",
   "  - A PE Loader vulnerability could allow an attacker to\n",
   "    execute arbitrary code with the privilege of the\n",
   "    logged-on user.\n",
   "\n",
   "  - A ASP.NET NULL byte termination vulnerability could\n",
   "    allow an attacker to retrieve contents from the web\n",
   "    server.\n",
   "\n",
   "  - A JIT compiler vulnerability could allow an attacker to\n",
   "    execute arbitrary code with the privilege of the\n",
   "    logged-on user."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for .NET Framework 1.0, 1.1\n",
   "and 2.0 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms07-040.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("dotnet_framework_version.nasl");
 script_require_ports("Services/www/ASP.Net");
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! port ) exit(0);

kb =  get_kb_item("www/" + port + "/Microsoft_.NET_Framework_Version");
if ( ! kb ) exit(0);

v = split(kb, sep:'.', keep:FALSE);
for ( i = 0 ; i < max_index(v) ; i ++ ) v[i] = int(v[i]);

if ( (v[0] == 1 && v[1] == 0 && v[2] < 3705) ||
     (v[0] == 1 && v[1] == 0 && v[2] == 3705 && v[3] < 6060)  || # 1.0SP3
      
     (v[0] == 1 && v[1] == 1 && v[2] < 4322) ||
     (v[0] == 1 && v[1] == 1 && v[2] == 4322 && v[3] < 2407) ||  # 1.1 SP1

     (v[0] == 2 && v[1] == 0 && v[2] < 50727 ) ||
     (v[0] == 2 && v[1] == 0 && v[2] == 50727 && v[3] < 832 ) ) security_hole(port);
