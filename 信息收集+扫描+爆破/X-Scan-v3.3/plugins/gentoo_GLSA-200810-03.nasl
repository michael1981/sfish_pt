# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200810-03.xml
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
 script_id(34678);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200810-03");
 script_cve_id("CVE-2008-2469");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200810-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200810-03
(libspf2: DNS response buffer overflow)


    libspf2 uses a fixed-length buffer to receive DNS responses and does
    not properly check the length of TXT records, leading to buffer
    overflows.
  
Impact

    A remote attacker could store a specially crafted DNS entry and entice
    a user or automated system using libspf2 to lookup that SPF entry (e.g.
    by sending an email to the MTA), possibly allowing for the execution of
    arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libspf2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-filter/libspf2-1.2.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2469');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200810-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200810-03] libspf2: DNS response buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libspf2: DNS response buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-filter/libspf2", unaffected: make_list("ge 1.2.8"), vulnerable: make_list("lt 1.2.8")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
