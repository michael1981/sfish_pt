# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(24249);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200701-13");
 script_cve_id("CVE-2006-5867", "CVE-2006-5974");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-13
(Fetchmail: Denial of Service and password disclosure)


    Neil Hoggarth has discovered that when delivering messages to a message
    delivery agent by means of the "mda" option, Fetchmail passes a NULL
    pointer to the ferror() and fflush() functions when refusing a message.
    Isaac Wilcox has discovered numerous means of plain-text password
    disclosure due to errors in secure connection establishment.
  
Impact

    An attacker could deliver a message via Fetchmail to a message delivery
    agent configured to refuse the message, and crash the Fetchmail
    process. SMTP and LMTP delivery modes are not affected by this
    vulnerability. An attacker could also perform a Man-in-the-Middle
    attack, and obtain plain-text authentication credentials of users
    connecting to a Fetchmail process.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All fetchmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/fetchmail-6.3.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5867');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5974');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-13] Fetchmail: Denial of Service and password disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Fetchmail: Denial of Service and password disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/fetchmail", unaffected: make_list("ge 6.3.6"), vulnerable: make_list("lt 6.3.6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
