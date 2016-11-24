#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16190);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2005-0094", "CVE-2005-0095", "CVE-2005-0173", "CVE-2005-0174",
	       "CVE-2005-0175", "CVE-2005-0211", "CVE-2005-0241");
 script_bugtraq_id(12275, 12276, 12412, 12433, 12432, 12431, 13434, 13435);
 script_xref(name:"OSVDB", value:"12886");
 script_xref(name:"OSVDB", value:"12887");
 script_xref(name:"OSVDB", value:"13054");
 script_xref(name:"OSVDB", value:"13319");
 script_xref(name:"OSVDB", value:"13345");
 script_xref(name:"OSVDB", value:"13346");
 script_xref(name:"OSVDB", value:"13732");

 script_name(english:"Squid < 2.5.STABLE8 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote Squid caching proxy is
affected by several security flaws :

  - There is a buffer overflow when handling the reply of a
    rogue gopher site. (CVE-2005-0094)

  - There is a denial of service vulnerability in the WCCP
    code of the remote proxy. (CVE-2005-0095)

  - There is a buffer overflow in the WCCP code that may 
    allow an attacker to execute arbitrary code on the 
    remote host. (CVE-2005-0211)

  - There is a flaw in the 'squid_ldap_auth' module that may
    allow an attacker to bypass authentication and to gain
    access to the remote proxy. (CVE-2005-0173)

  - There is a flaw in the way Squid parses HTTP reply 
    headers. (CVE-2005-0241)

  - There is a weakness that may allow for cache poisoning via
    HTTP response splitting. (CVE-2005-0175)

  - There is a weakness that may allow for cache poisoning via
    crafted malformed headers. (CVE-2005-0174)

Note that this may be a false-positive given the way the Squid team
handles releases.  Make sure that all the appropriate patches have
been applied." );
 script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Versions/v2/2.5/bugs/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Squid 2.5.STABLE8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 script_summary(english:"Determines squid version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Firewalls"); 
 script_dependencie("proxy_use.nasl");
 script_require_ports("Services/http_proxy", 3128, 8080);
 exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


port = get_kb_item("Services/http_proxy");
if(!port)
{
 if(get_port_state(3128)) port = 3128;
 else port = 8080;
}

if(get_port_state(port))
{
  res = http_get_cache(item:"/", port:port);
  if(res && egrep(pattern:"[Ss]quid/2\.([0-4]\.|5\.STABLE[0-7][^0-9])", string:res))
      security_hole(port);
}
