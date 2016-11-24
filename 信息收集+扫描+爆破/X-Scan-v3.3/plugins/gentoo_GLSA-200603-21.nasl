# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-21.xml
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
 script_id(21128);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200603-21");
 script_cve_id("CVE-2006-0058");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200603-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200603-21
(Sendmail: Race condition in the handling of asynchronous signals)


    ISS discovered that Sendmail is vulnerable to a race condition in
    the handling of asynchronous signals.
  
Impact

    An attacker could exploit this via certain crafted timing
    conditions.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Sendmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-mta/sendmail-8.13.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0058');
script_set_attribute(attribute: 'see_also', value: 'http://www.sendmail.com/company/advisory/index.shtml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200603-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200603-21] Sendmail: Race condition in the handling of asynchronous signals');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sendmail: Race condition in the handling of asynchronous signals');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-mta/sendmail", unaffected: make_list("ge 8.13.6"), vulnerable: make_list("lt 8.13.6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
