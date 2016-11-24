#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#



include("compat.inc");

if (description) {
  script_id(16141);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2004-1267","CVE-2004-1268","CVE-2004-1269","CVE-2004-1270", "CVE-2005-2874");
  script_bugtraq_id(11968, 12004, 12005, 12007, 12200, 14265);
  script_xref(name:"FLSA", value:"FEDORA-2004-559");
  script_xref(name:"FLSA", value:"FEDORA-2004-560");
  script_xref(name:"GLSA", value:"GLSA-200412-25");
  script_xref(name:"OSVDB", value:"12834");
  script_xref(name:"OSVDB", value:"12454");
  script_xref(name:"OSVDB", value:"12453");
  script_xref(name:"OSVDB", value:"12439");

  script_name(english:"CUPS < 1.1.23 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote print service is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is between 1.0.4 and 1.1.22 inclusive.  Such versions are prone
to multiple vulnerabilities :

  - A remotely exploitable buffer overflow in the 'hpgltops'
    filter that enable specially-crafted HPGL files can 
    execute arbitrary commands as the CUPS 'lp' account.

  - A local user may be able to prevent anyone from changing 
    his or her password until a temporary copy of the new 
    password file is cleaned up (lppasswd flaw).

  - A local user may be able to add arbitrary content to the 
    password file by closing the stderr file descriptor 
    while running lppasswd (lppasswd flaw).

  - A local attacker may be able to truncate the CUPS 
    password file, thereby denying service to valid clients 
    using digest authentication. (lppasswd flaw).

  - The application applys ACLs to incoming print jobs in a 
    case-sensitive fashion. Thus, an attacker can bypass 
    restrictions by changing the case in printer names when 
    submitting jobs. [Fixed in 1.1.21.]" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L700" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L1024" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L1023" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CUPS 1.1.23 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


  script_summary(english:"Checks version of CUPS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 George A. Theall");
  script_family(english:"Misc.");
  script_dependencie("http_version.nasl");
  script_require_keys("www/cups", "Settings/ParanoidReport");
  script_require_ports("Services/www", 631);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);

port = get_http_port(default:631);
if (!get_port_state(port)) exit(0);


# Check as long as it corresponds to a CUPS server.
banner = get_http_banner(port:port);
banner = strstr(banner, "Server: CUPS");
if (banner != NULL) {

  # Get the version number, if possible.
  banner = banner - strstr(banner, string("\n"));
  pat = "^Server: CUPS/?(.*)$";
  ver = eregmatch(string:banner, pattern:pat);
  if (isnull(ver)) exit(0);

  ver = chomp(ver[1]);
  if (ver =~ "^1\.(0(\.)?|1\.(1|2[0-2]))") 
    security_hole(port);
}
