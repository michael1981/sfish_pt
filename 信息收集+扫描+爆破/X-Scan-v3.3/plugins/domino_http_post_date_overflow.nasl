#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19238);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-1101");
  script_bugtraq_id(13130);
  script_xref(name:"OSVDB", value:"15364");

  script_name(english:"IBM Lotus Domino Server time/date Fields Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to a buffer overflow
vulnerability attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of Lotus
Domino Server that is prone to a buffer overflow attack triggered by
submitting a POST request with large amounts of data for certain date
/ time fields.  A remote attacker can reportedly exploit this issue to
crash the web server or possible execute arbitrary code on the
affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.ngssoftware.com/advisories/lotus-01.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0158.html" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?rs=899&uid=swg21202431" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Lotus Domino Server version 6.0.5 / 6.5.4 Maintenance
Release or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
  script_summary(english:"Checks for date fields overflow vulnerability in Lotus Domino Server");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if (!banner || "Lotus Domino" >!< banner) exit(0);


# Check the version number.
#
# nb: Litchfield claims 6.0.5 and 6.5.4 are affected, and earlier versions
#     may also be. Also note that there are no versions 6.1.x - 6.4.x per 
#     the Fix List at 
#     <http://www-10.lotus.com/ldd/r5fixlist.nsf/Public?OpenView>.
if (egrep(string:banner, pattern:"^Server: +Lotus-Domino/([0-5]\.|6\.(0\.[0-5]|5\.[0-4]))"))
  security_hole(port);
