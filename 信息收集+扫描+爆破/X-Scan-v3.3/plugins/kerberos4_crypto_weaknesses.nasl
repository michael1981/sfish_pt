#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Delivered-To: moderator for bugtraq@securityfocus.com
# To: kerberos-announce@MIT.EDU
# Subject: MITKRB5-SA-2003-004: Cryptographic weaknesses in Kerberos v4 protocol
# Reply-To: krbdev@mit.edu
# From: Tom Yu <tlyu@mit.edu>


include("compat.inc");

if(description)
{
 script_id(11511);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2003-0138");
 script_bugtraq_id(7113);
 script_xref(name:"OSVDB", value:"4869");

 script_name(english:"Kerberos 4 Realm Principle Impersonation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is using an authentication protocol with
cryptographic weaknesses." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Kerberos IV.

It has been demonstrated that the Kerberos IV protocol has inherent
design flaws that make it insecure to use." );
 script_set_attribute(attribute:"see_also", value:"http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2003-004-krb4.txt" );
 script_set_attribute(attribute:"solution", value:
"Use Kerberos 5 instead. If you run Kerberos 5 with Kerberos IV backward
compatibility, make sure you upgrade to version 1.3." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Check for kerberos");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 exit(0);
}


port = 750;

req = raw_string(0x04, 0x02) + "nessus" + raw_string(0) + "NESSUS.ORG" + raw_string(0) + raw_string(0x3e, 0x8c, 0x25, 0xDC, 0x78) + "xkrbtgt" + raw_string(0) + "NESSUS.ORG" + raw_string(0);
soc = open_sock_udp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:req);
r = recv(socket:soc, length:4096);
if(r && ord(r[0]) == 4)security_hole(port);
