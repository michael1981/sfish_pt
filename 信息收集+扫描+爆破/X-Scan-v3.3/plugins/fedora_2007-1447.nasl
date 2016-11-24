
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1447
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27718);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1447: balsa");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1447 (balsa)");
 script_set_attribute(attribute: "description", value: "Balsa is a GNOME email client which supports mbox, maildir, and mh
local mailboxes, and IMAP4 and POP3 remote mailboxes. Email can be
sent via sendmail or SMTP. Optional multithreading support allows for
non-intrusive retrieval and sending of mail. A finished GUI similar to
that of the Eudora email client supports viewing images inline, saving
message parts, viewing headers, adding attachments, moving messages,
and printing messages.

-
Update Information:

Balsa is not really listed in the list but it also lacked the verification of t
he server challenge.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-1558");
script_summary(english: "Check for the version of the balsa package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"balsa-2.3.17-2.fc7", release:"FC7") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
