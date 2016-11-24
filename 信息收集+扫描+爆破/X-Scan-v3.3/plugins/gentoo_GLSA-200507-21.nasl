# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-21.xml
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
 script_id(19323);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200507-21");
 script_cve_id("CVE-2005-2335");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-21
(fetchmail: Buffer Overflow)


    fetchmail does not properly validate UIDs coming from a POP3 mail
    server. The UID is placed in a fixed length buffer on the stack, which
    can be overflown.
  
Impact

    Very long UIDs returned from a malicious or compromised POP3
    server can cause fetchmail to crash, resulting in a Denial of Service,
    or allow arbitrary code to be placed on the stack.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All fetchmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/fetchmail-6.2.5.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://fetchmail.berlios.de/fetchmail-SA-2005-01.txt');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2335');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-21] fetchmail: Buffer Overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'fetchmail: Buffer Overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/fetchmail", unaffected: make_list("ge 6.2.5.2"), vulnerable: make_list("lt 6.2.5.2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
