
# Changes by Tenable:
#   - added script_name, revised description, added script dependency
#   - added code to only run if report paranoia is "Paranoid".
#   - fixed regex, added report function.
#   - updated title (6/25/09)
#   - changed plugin family (7/6/09)
#   - Updated to use compat.inc (11/20/2009)



include("compat.inc");

if (description)
{
script_id(24870);
script_version("$Revision: 1.6 $");

script_cve_id("CVE-2007-0247", "CVE-2007-0248");
script_bugtraq_id(22079, 22203);
script_xref(name:"OSVDB", value:"32823");
script_xref(name:"OSVDB", value:"39839");

 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by multiple denial of service 
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"Two vulnerabilities have been reported in Squid, which can be 
exploited by malicious people to cause a denial of service." );
 script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Versions/v2/2.6/squid-2.6.STABLE7-RELEASENOTES.html#s12" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to squid 2.6.STABLE7 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();


script_name(english:"Squid < 2.6.STABLE7 Multiple Remote DoS");
script_summary(english:"Determines squid version");
script_category(ACT_GATHER_INFO);
script_copyright(english: "(C) 2007-2009 Shu-Ting Ou <mindlovemoon@gmail.com>");
script_family(english:"Firewalls");
script_dependencies("proxy_use.nasl");
script_require_ports("Services/http_proxy",3128, 8080);
exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

# nb: only run the plugin if we're being paranoid to avoid false-positives,
#     which might arise because the software is open-source.
if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/http_proxy");
if(!port)port = 3128;
if(!get_port_state(port))port = 8080;

if(get_port_state(port))
{
 res = http_get_cache(item:"/", port:port);
 if(res && egrep(pattern:"[Ss]quid/2\.([0-5]\.|6\.STABLE[0-6][^0-9])", string:res))
   security_warning(port);
}
