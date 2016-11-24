
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9869
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(41613);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-9869: cyrus-imapd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9869 (cyrus-imapd)");
 script_set_attribute(attribute: "description", value: "The cyrus-imapd package contains the core of the Cyrus IMAP server.
It is a scaleable enterprise mail system designed for use from
small to large enterprise environments using standards-based
internet mail technologies.

A full Cyrus IMAP implementation allows a seamless mail and bulletin
board environment to be set up across multiple servers. It differs from
other IMAP server implementations in that it is run on 'sealed'
servers, where users are not normally permitted to log in and have no
system account on the server. The mailbox database is stored in parts
of the filesystem that are private to the Cyrus IMAP server. All user
access to mail is through software using the IMAP, POP3 or KPOP
protocols. It also includes support for virtual domains, NNTP,
mailbox annotations, and much more. The private mailbox database design
gives the server large advantages in efficiency, scalability and
administratability. Multiple concurrent read/write connections to the
same mailbox are permitted. The server supports access control lists on
mailboxes and storage quotas on mailbox hierarchies.

The Cyrus IMAP server supports the IMAP4rev1 protocol described
in RFC 3501. IMAP4rev1 has been approved as a proposed standard.
It supports any authentication mechanism available from the SASL
library, imaps/pop3s/nntps (IMAP/POP3/NNTP encrypted using SSL and
TLSv1) can be used for security. The server supports single instance
store where possible when an email message is addressed to multiple
recipients, SIEVE provides server side email filtering.

-
Update Information:

Fixed multiple stack-based buffer overflows in libsieve, which allowed context-
dependent attackers to cause a denial of service (crash) and possibly execute
arbitrary code via a crafted SIEVE script.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-3235");
script_summary(english: "Check for the version of the cyrus-imapd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"cyrus-imapd-2.3.15-1.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
